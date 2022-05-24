package zk

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	krb5client "github.com/jcmturner/gokrb5/v8/client"
	krb5config "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	krb5keytab "github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

type SASLConfig struct {
	Enable         bool
	KerberosConfig *KerberosConfig
}

type KerberosConfig struct {
	Keytab       []byte
	Krb5         string
	PrincipalStr string
}

const (
	TokIdKrbApReq    = 256
	GssapiGenericTag = 0x60
)

type GssapiStep int64

const (
	GssapiInitial GssapiStep = iota
	GssapiVerify
	GssapiFinish
)

type KerberosAuth struct {
	Config *KerberosConfig
	ticket messages.Ticket
	encKey types.EncryptionKey
	step   GssapiStep
}

type Principal struct {
	Realm      string
	Components []string
}

// NewPrincipal 根据字符串生成 principal 实例
// 参考微软 RFC6806 https://datatracker.ietf.org/doc/html/rfc6806
// 参考微软 RFC3244 https://datatracker.ietf.org/doc/html/rfc3244
// 核心是两种模型： primary/instance@realm primary@realm
func NewPrincipal(principalStr string) (*Principal, error) {
	principal := &Principal{}
	split := strings.Split(principalStr, "@")
	if len(split) != 2 {
		return nil, errors.New("principal 字符串格式错误！无法解析的realm")
	}
	principal.Realm = split[1]
	split1 := strings.Split(split[0], "/")
	if len(split1) == 0 {
		return nil, errors.New("principal 字符串格式错误！无法解析的primary")
	}
	principal.Components = split1
	return principal, nil
}

func newKerberosClient(c *KerberosConfig) (*krb5client.Client, *Principal, error) {
	if c == nil {
		return nil, nil, fmt.Errorf("config nil error")
	}
	principal, err := NewPrincipal(c.PrincipalStr)
	if err != nil {
		return nil, nil, err
	}
	if krb5cfg, err := krb5config.NewFromString(c.Krb5); err != nil {
		return nil, principal, err
	} else {
		keytab := krb5keytab.New()
		if err := keytab.Unmarshal(c.Keytab); err != nil {
			return nil, principal, err
		} else {
			return krb5client.NewWithKeytab(principal.Components[0], principal.Realm, keytab, krb5cfg), principal, nil
		}
	}
}

func (k *KerberosAuth) initSecContext(bytes []byte, krbCli *krb5client.Client) ([]byte, error) {
	switch k.step {
	case GssapiInitial:
		if krb5Token, err := createKrb5Token(
			krbCli.Credentials.Domain(),
			krbCli.Credentials.CName(),
			k.ticket, k.encKey,
		); err != nil {
			return nil, err
		} else {
			k.step = GssapiVerify
			return appendGSSAPIHeader(krb5Token)
		}

	case GssapiVerify:
		wrapTokenReq := gssapi.WrapToken{}
		if err := wrapTokenReq.Unmarshal(bytes, true); err != nil {
			return nil, err
		}
		// Validate response.
		isValid, err := wrapTokenReq.Verify(k.encKey, keyusage.GSSAPI_ACCEPTOR_SEAL)
		if !isValid {
			return nil, err
		}

		wrapTokenResponse, err := gssapi.NewInitiatorWrapToken(wrapTokenReq.Payload, k.encKey)
		if err != nil {
			return nil, err
		}
		k.step = GssapiFinish
		return wrapTokenResponse.Marshal()
	}
	return nil, nil
}

func (k *KerberosAuth) Authorize(ctx context.Context, c *Conn) error {
	// create kerberos client
	krbCli, principal, err := newKerberosClient(c.saslConfig.KerberosConfig)
	if err != nil {
		return fmt.Errorf("failed to create kerberos client, err: %s", err)
	}
	// kerberos client login for TGT token
	if err = krbCli.Login(); err != nil {
		return fmt.Errorf("kerberos client fails to login, err: %s", err)
	}
	defer krbCli.Destroy()

	spn := strings.Join(principal.Components, "/")

	if k.ticket, k.encKey, err = krbCli.GetServiceTicket(spn); err != nil {
		return fmt.Errorf("kerberos client fails to obtain service ticket, err: %s", err)
	}
	var (
		recvBytes []byte = nil
		packBytes []byte = nil
	)

	// client handshakes with zookeeper service
	k.step = GssapiInitial
	for {
		if packBytes, err = k.initSecContext(recvBytes, krbCli); err != nil {
			c.logger.Printf("failed to init session context while performing kerberos authentication, err: %s", err)
			return err
		}

		var (
			saslReq  = &setSaslRequest{string(packBytes)}
			saslRsp  = &setSaslResponse{}
			recvChan <-chan response
		)
		if recvChan, err = c.sendRequest(opSetSASL, saslReq, saslRsp, nil); err != nil {
			c.logger.Printf("failed to send setSASL request while performing kerberos authentication, err: %s", err)
			return err
		}

		select {
		case res := <-recvChan:
			if res.err != nil {
				c.logger.Printf("failed to recv setSASL response while performing kerberos authentication, err: %s", res.err)
				return res.err
			}
		case <-c.closeChan:
			c.logger.Printf("recv closed, cancel recv setSASL response while preforming kerberos authentication")
			return nil
		case <-c.shouldQuit:
			c.logger.Printf("should quit, cancel recv setSASL response while preforming kerberos authentication")
			return nil
		case <-ctx.Done():
			c.logger.Printf("context is done while performing kerberos authentication")
			return ctx.Err()
		}

		if k.step == GssapiFinish {
			return nil
		} else if k.step == GssapiVerify {
			recvBytes = []byte(saslRsp.Token)
		}
	}
}

/*
*
* Construct Kerberos AP_REQ package, conforming to RFC-4120
* https://tools.ietf.org/html/rfc4120#page-84
*
 */
func createKrb5Token(
	domain string, cname types.PrincipalName,
	ticket messages.Ticket, encKey types.EncryptionKey) ([]byte, error) {
	if auth, err := types.NewAuthenticator(domain, cname); err != nil {
		return nil, err
	} else {

		auth.Cksum = types.Checksum{
			CksumType: chksumtype.GSSAPI,
			Checksum:  createCheckSum(),
		}
		APReq, err := messages.NewAPReq(ticket, encKey, auth)
		if err != nil {
			return nil, err
		}
		aprBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(aprBytes, TokIdKrbApReq)
		reqBytes, err := APReq.Marshal()
		if err != nil {
			return nil, err
		}
		return append(aprBytes, reqBytes...), nil
	}
}

/*
*
* Append the GSS-API header to the payload, conforming to RFC-2743
* Section 3.1, Mechanism-Independent Token Format
*
* https://tools.ietf.org/html/rfc2743#page-81
*
* GSSAPIHeader + <specific mechanism payload>
*
 */
func appendGSSAPIHeader(payload []byte) ([]byte, error) {
	oidBytes, err := asn1.Marshal(gssapi.OIDKRB5.OID())
	if err != nil {
		return nil, err
	}
	lengthBytes := asn1tools.MarshalLengthBytes(len(oidBytes) + len(payload))
	gssapiHeader := append([]byte{GssapiGenericTag}, lengthBytes...)
	gssapiHeader = append(gssapiHeader, oidBytes...)
	gssapiPacket := append(gssapiHeader, payload...)
	return gssapiPacket, nil
}

func createCheckSum() []byte {
	var checkSum = make([]byte, 24)
	binary.LittleEndian.PutUint32(checkSum[:4], 16)
	for _, flag := range []uint32{
		uint32(gssapi.ContextFlagInteg),
		uint32(gssapi.ContextFlagConf),
	} {
		binary.LittleEndian.PutUint32(checkSum[20:24],
			binary.LittleEndian.Uint32(checkSum[20:24])|flag,
		)
	}
	return checkSum
}
