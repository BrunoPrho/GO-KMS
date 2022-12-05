package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"golang.org/x/crypto/sha3"
	"log"
	"os"
)

var (
	DebugLog    *log.Logger
	WarningLog  *log.Logger
	InfoLog     *log.Logger
	ErrorLog    *log.Logger
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorReset  = "\033[0m"
	// colorPurple = "\033[35m"
	// colorCyan = "\033[36m"
	colorWhite = "\033[37m"
)

type KMSObj struct {
	svc *kms.KMS
}

type KMSInstance interface {
	Connect() error
	ListKeys() error
	DescribeKey(*kms.KeyListEntry) error
	Wrap(*kms.KeyListEntry, []byte) (*kms.EncryptOutput, error)
	Unwrap(*kms.KeyListEntry, *kms.EncryptOutput) (*kms.DecryptOutput, error)
}

func (obj *KMSObj) DescribeKey(ikey *kms.KeyListEntry) error {
	InfoLog.Println(
		colorReset, "Key Id", colorRed, *ikey.KeyId,
		colorReset, "Key Arn", colorBlue, *ikey.KeyArn)
	input := &kms.DescribeKeyInput{KeyId: aws.String(*ikey.KeyId)}
	result, err := obj.svc.DescribeKey(input)
	if err != nil {
		ErrorLog.Println("Error ")
		return err
	}
	InfoLog.Println("DescribeKey", result)
	return nil
}

func (obj KMSObj) ProcessEncryptionTest(ikey *kms.KeyListEntry) error {

	inputEnc := &kms.EncryptInput{
		KeyId:     aws.String(*ikey.KeyId),
		Plaintext: []byte("this must be secret protected by AWS envelop encryption!"),
	}
	InfoLog.Println(colorBlue, "Initial Clear text:", colorRed, string(inputEnc.Plaintext), colorReset)
	// h := make([]byte, 32)
	// Compute a 64-byte hash of buf and put it in h.
	h := sha3.Sum256(inputEnc.Plaintext)
	InfoLog.Println(colorBlue, "SHA3 Initial Clear text:", colorRed, hex.EncodeToString(h[:32]), colorReset)

	cryptogram, errEnc := obj.svc.Encrypt(inputEnc)
	if errEnc != nil {
		ErrorLog.Println("Error : ", errEnc.Error())
		return errEnc
	} else {
		InfoLog.Println("Cryptogram:", cryptogram)

		inputDec := &kms.DecryptInput{
			CiphertextBlob: cryptogram.CiphertextBlob,
			KeyId:          aws.String(*ikey.KeyId),
		}
		clearText, errDec := obj.svc.Decrypt(inputDec)
		InfoLog.Println(colorYellow, "Decrypt Done:")
		if errDec != nil {
			ErrorLog.Println("Error ")
			return errDec
		} else {
			InfoLog.Println(colorBlue, "Clear Unwrapped text:", colorRed, string(clearText.Plaintext), colorReset)
			hc := sha3.Sum256(clearText.Plaintext)
			DebugLog.Println(colorBlue, "SHA3 Unwrapped  text:", colorRed, hex.EncodeToString(hc[:32]), colorReset)
		}
	}
	return nil
}
func (obj *KMSObj) Unwrap(ikey *kms.KeyListEntry, wrappedDek *kms.EncryptOutput) (*kms.DecryptOutput, error) {
	inputDec := &kms.DecryptInput{
		CiphertextBlob: wrappedDek.CiphertextBlob,
		KeyId:          aws.String(*ikey.KeyId),
	}
	unwrapDek, errDec := obj.svc.Decrypt(inputDec)
	InfoLog.Println(colorYellow, "Decrypt Done:")
	if errDec != nil {
		ErrorLog.Println("Error ")
	} else {
		InfoLog.Println(colorBlue, "Unwrapped Clear DEK:", colorRed, hex.EncodeToString(unwrapDek.Plaintext), colorReset)
		hc := sha3.Sum256(unwrapDek.Plaintext)
		DebugLog.Println(colorBlue, "SHA3 Unwrapped Clear DEK:", colorRed, hex.EncodeToString(hc[:32]), colorReset)
	}
	return unwrapDek, nil
}
func (obj *KMSObj) Wrap(ikey *kms.KeyListEntry, dek []byte) (*kms.EncryptOutput, error) {
	inputEnc := &kms.EncryptInput{
		KeyId:     aws.String(*ikey.KeyId),
		Plaintext: dek,
	}
	// InfoLog.Println(colorBlue, "Initial Clear DEK:", colorRed, string(inputEnc.Plaintext), colorReset)
	// Compute SHA-3 input
	h := sha3.Sum256(inputEnc.Plaintext)
	InfoLog.Println(colorBlue, "SHA3 Initial DEK:", colorRed, hex.EncodeToString(h[:32]), colorReset)

	wrappedDek, errEnc := obj.svc.Encrypt(inputEnc)
	if errEnc != nil {
		ErrorLog.Println("Error : ", errEnc.Error())
		return nil, errors.New("Error Encrypting with KMS")
	} else {
		InfoLog.Println("Wrapped DEK:", wrappedDek)

	}
	return wrappedDek, nil
}
func (obj *KMSObj) Connect() error {
	var value = error(nil)
	// Initialize a session from the shared credentials file ~/.aws/credentials.
	awsSession, err := session.NewSession(&aws.Config{
		Region: aws.String("ap-southeast-2")},
	)

	if err != nil {
		value = err
		ErrorLog.Println("Error Done")
	} else { // List KMS service client
		obj.svc = kms.New(awsSession)
		value = nil
	}
	DebugLog.Println("Connection Done")
	return value

}

func init() {
	file, err := os.OpenFile("LOG.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		ErrorLog.Println("Error : ", err.Error())
	}
	DebugLog = log.New(file, colorWhite+"INFO: "+colorReset, log.Ldate|log.Ltime|log.Lshortfile)
	DebugLog.SetOutput(os.Stdout)

	InfoLog = log.New(file, colorBlue+"INFO: "+colorReset, log.Ldate|log.Ltime|log.Lshortfile)
	InfoLog.SetOutput(os.Stdout)

	WarningLog = log.New(file, colorYellow+"WARNING: "+colorReset, log.Ldate|log.Ltime|log.Lshortfile)
	WarningLog.SetOutput(os.Stdout)

	ErrorLog = log.New(file, colorRed+"ERROR: "+colorReset, log.Ldate|log.Ltime|log.Lshortfile)
	ErrorLog.SetOutput(os.Stdout)
}

func main() {
	var KMSobjinstance KMSObj

	err0 := KMSobjinstance.Connect()
	if err0 != nil {
		return
	}
	input := &kms.ListKeysInput{}
	result, err := KMSobjinstance.svc.ListKeys(input)

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case kms.ErrCodeDependencyTimeoutException:
				ErrorLog.Println(kms.ErrCodeDependencyTimeoutException, aerr.Error())
			case kms.ErrCodeInternalException:
				ErrorLog.Println(kms.ErrCodeInternalException, aerr.Error())
			case kms.ErrCodeInvalidMarkerException:
				ErrorLog.Println(kms.ErrCodeInvalidMarkerException, aerr.Error())
			default:
				ErrorLog.Println(aerr.Error())
			}
		} else {
			// Message from an error.
			ErrorLog.Println(err.Error())
		}
		return
	}

	for _, ikey := range result.Keys {
		ret := KMSobjinstance.DescribeKey(ikey)
		ret = KMSobjinstance.ProcessEncryptionTest(ikey)
		if ret != nil {
			InfoLog.Println(colorYellow, "-----------------------------------------", colorReset)
			// AES GCM
			dek := make([]byte, 32)
			_, errdek := rand.Read(dek)
			InfoLog.Println(colorBlue, "Key:", colorRed, hex.EncodeToString(dek))
			plaintext := []byte("This is a secret protected by AES GCM DEK generated%!")
			InfoLog.Println(colorBlue, "Message Clear:", colorRed, string(plaintext))

			block, err := aes.NewCipher(dek)
			if err != nil {
				ErrorLog.Println("Error : ", err.Error())
			}

			// AES GCM with 12 bytes Nonce
			nonce := make([]byte, 12)
			nonce, err = hex.DecodeString("79ca9fc9431e80aa512efbe9")
			if err != nil {
				ErrorLog.Println("Error : ", err.Error())
			}

			aesgcm, err := cipher.NewGCM(block)
			if err != nil {
				ErrorLog.Println("Error : ", err.Error())
			}

			ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
			InfoLog.Println("Encrypted Text :, nonce = \n", string(ciphertext), string(nonce))
			plaintextAes, err := aesgcm.Open(nil, nonce, ciphertext, nil)
			if err != nil {
				ErrorLog.Println("Error : ", err.Error())
			}

			InfoLog.Println("Clear Decrypted Text: ", colorRed, string(plaintextAes))
			InfoLog.Println(colorYellow, "-----------------------------------------", colorReset)

			Dek64 := base64.StdEncoding.EncodeToString(dek)
			if errdek != nil {
				ErrorLog.Println("Error : ", errdek.Error())
				return
			}
			InfoLog.Println("DEK :", colorRed, hex.EncodeToString(dek))
			InfoLog.Println(colorYellow, "-------The DEK is wrapped by a CMK-------", colorReset)
			wrappedDek, err := KMSobjinstance.Wrap(ikey, dek)
			if err != nil {
				ErrorLog.Println("Error ")
			} else {
				unwrapDek, errDec := KMSobjinstance.Unwrap(ikey, wrappedDek)
				if errDec != nil {
					ErrorLog.Println("Error ")
				} else {
					InfoLog.Println(colorBlue, "Unwrapped Clear DEK:", colorRed, hex.EncodeToString(unwrapDek.Plaintext), colorReset)
					hc := sha3.Sum256(unwrapDek.Plaintext)
					DebugLog.Println(colorBlue, "SHA3 Unwrapped Clear DEK:", colorRed, hex.EncodeToString(hc[:32]), colorReset)
				}
				unwrapDek64 := base64.StdEncoding.EncodeToString(unwrapDek.Plaintext)
				InfoLog.Println("Base 64 DEK and Unwrapped DEK ", colorRed, Dek64, " ----> ", colorYellow, unwrapDek64)
				InfoLog.Println(colorYellow, "-----------------------------------------", colorReset)
			}
		}
	}

}
