/*
Package cmd is the root package.
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/spf13/cobra"
)

const (
	issuedAtBuffer int64 = 10
)

var (
	privateKeyFile   string
	privateKeyStdin  bool
	issuedAtNow      bool
	expiresInSeconds int64
	audience         string
	id               string
	issuer           string
	notBefore        int64
	subject          string
	keyID            string
)

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a JWT quickly and easily",
	Run: func(cmd *cobra.Command, args []string) {
		if err := validateCreateParams(); err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}

		var privateKey []byte
		var err error
		if privateKeyFile == "-" || privateKeyStdin {
			privateKey, err = ioutil.ReadAll(os.Stdin)
			if err != nil {
				fmt.Printf("error reading from stdin: %v\n", err)
				os.Exit(1)
			}
		} else {
			privateKey, err = ioutil.ReadFile(privateKeyFile)
			if err != nil {
				fmt.Printf("error reading private key file: %v\n", err)
				os.Exit(1)
			}
		}

		nowUnix := time.Now().Unix()
		standardClaims := jwt.StandardClaims{}

		if expiresInSeconds > 0 {
			standardClaims.ExpiresAt = nowUnix + expiresInSeconds
		}
		if issuedAtNow {
			standardClaims.IssuedAt = nowUnix - issuedAtBuffer
		}

		standardClaims.Audience = audience
		standardClaims.Id = id
		standardClaims.Issuer = issuer
		standardClaims.NotBefore = notBefore
		standardClaims.Subject = subject

		token, err := generateJWTFromPrivateKey(standardClaims, keyID, privateKey)
		if err != nil {
			fmt.Printf("error generating JWT: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(token)
	},
}

func init() {
	rootCmd.AddCommand(createCmd)

	createCmd.Flags().StringVarP(&privateKeyFile, "private-key-file", "p", "", "Private key file")
	createCmd.Flags().BoolVar(&privateKeyStdin, "private-key-stdin", false, "Pass in the private key through stdin")
	createCmd.Flags().BoolVarP(&issuedAtNow, "issued-at-now", "i", false, "Set issued at (iat) to now")
	createCmd.Flags().Int64Var(&expiresInSeconds, "expires-in-seconds", 0, "How many seconds the token is valid for")
	createCmd.Flags().StringVar(&audience, "audience", "", "Audience claim")
	createCmd.Flags().StringVar(&id, "id", "", "ID claim")
	createCmd.Flags().StringVar(&issuer, "issuer", "", "Issuer claim")
	createCmd.Flags().Int64Var(&notBefore, "not-before", 0, "Not before claim")
	createCmd.Flags().StringVar(&subject, "subject", "", "Subject claim")
	createCmd.Flags().StringVar(&keyID, "key-id", "", "Key ID")
}

func validateCreateParams() error {
	if privateKeyFile == "" && !privateKeyStdin {
		return fmt.Errorf("no private key specified")
	}

	return nil
}

func generateJWTFromPrivateKey(claims jwt.StandardClaims, keyID string, privateKey []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if keyID != "" {
		token.Header["kid"] = keyID
	}

	decodedPem, _ := pem.Decode(privateKey)
	if decodedPem == nil {
		return "", fmt.Errorf("unexpected empty decoded pem")
	}

	rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(decodedPem.Bytes)
	if err != nil {
		return "", fmt.Errorf("error parsing private key: %w", err)
	}

	tokenSigned, err := token.SignedString(rsaPrivateKey)
	if err != nil {
		return "", fmt.Errorf("error signing JWT token: %w", err)
	}

	return tokenSigned, nil
}
