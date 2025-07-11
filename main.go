package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	gnarkmimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/labstack/echo/v4"
)

type PasswordCircuit struct {
	Password [1]frontend.Variable 
	Hash frontend.Variable `gnark:",public"`
}

func (circuit *PasswordCircuit) Define(api frontend.API) error {
	hasher, err := mimc.NewMiMC(api)

	if err != nil {
		return err
	}
	for _, salt := range fixedSalt {
		hasher.Write(salt)
	}
 
	for _, pass := range circuit.Password {
		hasher.Write(pass)
	}

	hasher.Write(nonce)
	hash := hasher.Sum()
	api.AssertIsEqual(hash, circuit.Hash)

	return nil
}

type Input struct {
	Password int `json:"password"`
}

type Response struct {
	Password	int		`json:"password"`
	Hash		string 	`json:"hash"`
	Nonce 		string 	`json:"nonce"`
	Valid		bool	`json:"valid"`
	Error		string	`json:"error,omitempty"`
}

var (
	ccs constraint.ConstraintSystem
	pk  groth16.ProvingKey
	vk  groth16.VerifyingKey
	fixedSalt    [16]byte
	fixedSaltVar [16]frontend.Variable
	expectedHash big.Int
	nonce 		 *big.Int
)

func initZK() {
	password := int64(1234)
	fixedSalt = [16]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00}
	nonce, _ = generateNonce()

	hasher := gnarkmimc.NewMiMC()
	for _, b := range fixedSalt {
		hasher.Write([]byte{b})
	}
	hasher.Write(bigIntToBytes(big.NewInt(password)))
	hasher.Write(bigIntToBytes(nonce))
	digest := hasher.Sum(nil)
	expectedHash.SetBytes(digest)

	for i, b := range fixedSalt {
		fixedSaltVar[i] = big.NewInt(int64(b))
	}

	var circuit PasswordCircuit
	var err error
	ccs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatal(err)
	}

	pk, vk, err = groth16.Setup(ccs)
	if err != nil {
		log.Fatal(err)
	}
}

func bigIntToBytes (x *big.Int) []byte {
	var frEl fr.Element
	frEl.SetBigInt(x)
	arr := frEl.Bytes()
	return arr[:]
}

func generateSalt() ([16]frontend.Variable, []byte, error) {
	var salt [16]frontend.Variable
	rawSalt := make([]byte, 16)

	_, err := rand.Read(rawSalt)
	if err != nil {
		return salt, nil, err
	}

	for i := range rawSalt {
		salt[i] = big.NewInt(int64(rawSalt[i]))
	}

	return salt, rawSalt, nil
}

func generateNonce() (*big.Int, error) {
	nonceBytes := make([]byte, 4)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(nonceBytes), nil
}

func logAttempt(time time.Time, result string, step string) {
	f, err := os.OpenFile("log.txt", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil  {
		fmt.Println(err)
		return
	}

	line := "Time: " + time.Format("2006-01-02 03:04:05PM") + ", Result " + result + ", Step: " + step
	_, err = fmt.Fprintln(f, line)
	if err != nil {
		fmt.Println(err)
		f.Close()
		return
	}

	err = f.Close()
	if err != nil {
		fmt.Println(err)
		return
	}
}

func proveHandler(c echo.Context) error {
	initZK()

	var input Input
	err := c.Bind(&input);
	if err != nil {
		logAttempt(time.Now().Local(), "fail", "input")
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid input"})
	}

	passwordInt := new(big.Int).SetInt64(int64(input.Password))

	hasher := gnarkmimc.NewMiMC()

	for i := 0; i < len(fixedSalt); i++ {
		hasher.Write(([]byte{fixedSalt[i]}))
	}
	hasher.Write(bigIntToBytes(passwordInt))
	hasher.Write(bigIntToBytes(nonce))

	digest := hasher.Sum(nil)
	var hash big.Int
	hash.SetBytes(digest)
	

	assignment := PasswordCircuit {
		Password: [1]frontend.Variable {passwordInt},
		Hash: expectedHash,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		logAttempt(time.Now().Local(), "fail", "witness generation")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "witness creation failed"})
	}
	publicWitness, err := witness.Public()
	if err != nil {
		logAttempt(time.Now().Local(), "fail", "public witness")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "public witness error"})
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		logAttempt(time.Now().Local(), "fail", "proof generation")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "proof generation error"})
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		logAttempt(time.Now().Local(), "fail", "verification")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "verification failed"})
	} 
	
	response := Response{
		Password:	input.Password,
		Hash:     	hash.String(),
		Nonce: 		nonce.Text(16),
		Valid:		true,
	}

	logAttempt(time.Now().Local(), "success", "verification")
	return c.JSON(http.StatusOK, response)
}

func main() {
	//initZK()
	e := echo.New()
	e.POST("/prove", proveHandler)
	e.Logger.Fatal(e.Start(":8080"))
}