/*
Package cmd is the root package.
Copyright © 2022 Thomas Stringer <thomas@trstringer.com>

*/
package cmd

import (
	"bufio"
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
	issuedAtNow      bool
	expiresInSeconds int64
	audience         string
	id               string
	issuer           string
	notBefore        int64
	subject          string
)

var rootCmd = &cobra.Command{
	Use:   "jwt-creator",
	Short: "Create a JWT quickly and easily",
	Long: `This CLI allows you to quickly and easily
create JWTs.`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := validateParams(); err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}

		var privateKey []byte
		var err error
		if privateKeyFile == "-" {
			privateKey, _, err = bufio.NewReader(os.Stdin).ReadLine()
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

		token, err := generateJWTFromPrivateKey(standardClaims, privateKey)
		if err != nil {
			fmt.Printf("error generating JWT: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(token)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	rootCmd.Flags().StringVarP(&privateKeyFile, "private-key-file", "p", "", "Private key file")
	rootCmd.Flags().BoolVarP(&issuedAtNow, "issued-at-now", "i", false, "Set issued at (iat) to now")
	rootCmd.Flags().Int64Var(&expiresInSeconds, "expires-in-seconds", 0, "How many seconds the token is valid for")
	rootCmd.Flags().StringVar(&audience, "audience", "", "Audience claim")
	rootCmd.Flags().StringVar(&id, "id", "", "ID claim")
	rootCmd.Flags().StringVar(&issuer, "issuer", "", "Issuer claim")
	rootCmd.Flags().Int64Var(&notBefore, "not-before", 0, "Not before claim")
	rootCmd.Flags().StringVar(&subject, "subject", "", "Subject claim")
}

func validateParams() error {
	if privateKeyFile == "" {
		return fmt.Errorf("no private key specified")
	}

	return nil
}

func generateJWTFromPrivateKey(claims jwt.StandardClaims, privateKey []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

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
