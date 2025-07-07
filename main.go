package main

import (
	"log"
	"math/big"
	"net/http"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/labstack/echo/v4"
)

type PasswordCircuit struct {
	Password frontend.Variable 
	Hash frontend.Variable `gnark:",public"`
}

func (circuit *PasswordCircuit) Define(api frontend.API) error {
	api.Mul(circuit.Password, circuit.Hash)
	return nil
}

type Input struct {
	Password int `json:"password"`
}

type Response struct {
	Password	int		`json:"x"`
	Hash		int 	`json:"y"`
	Valid		bool	`json:"valid"`
	Error		string	`json:"error,omitempty"`
}

var (
	ccs constraint.ConstraintSystem
	pk  groth16.ProvingKey
	vk  groth16.VerifyingKey
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
}

func proveHandler(c echo.Context) error {
	var input Input
	err := c.Bind(&input);
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid input"})
	}

	password := input.Password
	hash := 1 * 2 * 3 * 4

	assignment := PasswordCircuit {
		Password: big.NewInt(int64(password)),
		Hash: big.NewInt(int64(hash)),
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "witness creation failed"})
	}
	publicWitness, err := witness.Public()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "public witness error"})
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "proof generation error"})
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "verification failed"})
	} 
	
	response := Response{
		Password:	password,
		Hash:     	hash,
		Valid:		true,
	}
	return c.JSON(http.StatusOK, response)
}

func main() {
	initZK()

	e := echo.New()
	e.POST("/prove", proveHandler)
	e.Logger.Fatal(e.Start(":8080"))
}