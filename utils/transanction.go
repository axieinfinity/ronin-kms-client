package utils

import (
	"bytes"
	"math/big"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
)

func RlpEncode(tx *types.Transaction, chainID *big.Int) ([]byte, error) {
	data := new(bytes.Buffer)
	var txData interface{}

	if chainID == nil { // homestead
		txData = []interface{}{
			tx.Nonce(),
			tx.GasPrice(),
			tx.Gas(),
			tx.To(),
			tx.Value(),
			tx.Data(),
		}
	} else { // london
		if tx.Type() == types.LegacyTxType {
			txData = []interface{}{
				tx.Nonce(),
				tx.GasPrice(),
				tx.Gas(),
				tx.To(),
				tx.Value(),
				tx.Data(),
				chainID, uint(0), uint(0),
			}
		} else if tx.Type() == types.AccessListTxType {
			data.Write([]byte{tx.Type()})
			txData = []interface{}{
				chainID,
				tx.Nonce(),
				tx.GasPrice(),
				tx.Gas(),
				tx.To(),
				tx.Value(),
				tx.Data(),
				tx.AccessList(),
			}
		} else { // types.DynamicFeeTxType
			data.Write([]byte{tx.Type()})
			txData = []interface{}{
				chainID,
				tx.Nonce(),
				tx.GasTipCap(),
				tx.GasFeeCap(),
				tx.Gas(),
				tx.To(),
				tx.Value(),
				tx.Data(),
				tx.AccessList(),
			}
		}
	}
	if err := rlp.Encode(data, txData); err != nil {
		return nil, err
	}

	return data.Bytes(), nil
}
