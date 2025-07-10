package main

import (
	"crypto/rand"
	"encoding/hex"
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
	Salt [16]frontend.Variable
}

func (circuit *PasswordCircuit) Define(api frontend.API) error {
	hasher, err := mimc.NewMiMC(api)

	if err != nil {
		return err
	}
	for _, salt := range circuit.Salt {
		hasher.Write(salt)
	}
 
	for _, pass := range circuit.Password {
		hasher.Write(pass)
	}

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
	Salt 		string 	`json:"salt"`
	Valid		bool	`json:"valid"`
	Error		string	`json:"error,omitempty"`
}

var (
	ccs constraint.ConstraintSystem
	pk  groth16.ProvingKey
	vk  groth16.VerifyingKey
	//storedHash big.Int
	//storedSalt [16]frontend.Variable
	//rawSalt []byte
)

func initZK() {
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
	
	//storedSalt, rawSalt, err = generateSalt()
	//if err != nil {
	//	log.Fatal("salt generation error", err)
	//}

	//passwordInt := new(big.Int).SetInt64(1234)
	
	//hasher := gnarkmimc.NewMiMC()
	//for i := 0; i < len(rawSalt); i++ {
	//	hasher.Write([]byte{rawSalt[i]})
	//}
	//hasher.Write(bigIntToBytes(passwordInt))

	//digest := hasher.Sum(nil)
	//storedHash.SetBytes(digest)
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
	var input Input
	err := c.Bind(&input);
	if err != nil {
		logAttempt(time.Now().Local(), "fail", "input")
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid input"})
	}

	passwordInt := new(big.Int).SetInt64(int64(input.Password))

	hasher := gnarkmimc.NewMiMC()
	salt, rawSalt, err := generateSalt()
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "salt generation error"})
	}
	
	for i := 0; i < len(rawSalt); i++ {
		hasher.Write(([]byte{rawSalt[i]}))
	}
	hasher.Write((bigIntToBytes(passwordInt)))

	digest := hasher.Sum(nil)
	var hash big.Int
	hash.SetBytes(digest)


	assignment := PasswordCircuit {
		Password: [1]frontend.Variable {passwordInt},
		Hash: hash,
		Salt: salt,
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
		Salt: 		hex.EncodeToString(rawSalt),
		Valid:		true,
	}

	logAttempt(time.Now().Local(), "success", "verification")
	return c.JSON(http.StatusOK, response)
}

func main() {
	initZK()
	e := echo.New()
	e.POST("/prove", proveHandler)
	e.Logger.Fatal(e.Start(":8080"))
}