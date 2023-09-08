package ante

import (
	"fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	accountante "github.com/cosmos/cosmos-sdk/x/auth/ante"
	authenticatorkeeper "github.com/osmosis-labs/osmosis/v19/x/authenticator/keeper"
)

// Consume parameter-defined amount of gas for each signature according to the passed-in SignatureVerificationGasConsumer function
// before calling the next AnteHandler
// CONTRACT: Pubkeys are set in context for all signers before this decorator runs
// CONTRACT: Tx must implement SigVerifiableTx interface
type SigGasConsumeDecorator struct {
	ak                  accountante.AccountKeeper
	authenticatorKeeper *authenticatorkeeper.Keeper
	sigGasConsumer      accountante.SignatureVerificationGasConsumer
}

func NewSigGasConsumeDecorator(
	ak accountante.AccountKeeper,
	authk *authenticatorkeeper.Keeper,
	sigGasConsumer accountante.SignatureVerificationGasConsumer,
) SigGasConsumeDecorator {
	return SigGasConsumeDecorator{
		ak:                  ak,
		authenticatorKeeper: authk,
		sigGasConsumer:      sigGasConsumer,
	}
}

func (sgcd SigGasConsumeDecorator) AnteHandle(
	ctx sdk.Context,
	tx sdk.Tx,
	simulate bool,
	next sdk.AnteHandler,
) (newCtx sdk.Context, err error) {
	sigTx, ok := tx.(sdk.FeeTx)
	if !ok {
		return ctx, sdkerrors.Wrap(sdkerrors.ErrTxDecode, "invalid transaction type")
	}

	params := sgcd.ak.GetParams(ctx)

	//fp := sigTx.FeePayer()
	//deductFeesFromAcc := sgcd.ak.GetAccount(ctx, fp)

	for msgIndex, msg := range tx.GetMsgs() {
		authenticators, err := sgcd.authenticatorKeeper.GetAuthenticatorsForAccount(ctx, msg.GetSigners()[0])
		if err != nil {
			return sdk.Context{}, err
		}

		if len(authenticators) == 0 {
			authenticators = append(authenticators, sgcd.authenticatorKeeper.AuthenticatorManager.GetDefaultAuthenticator())
		}

		// before we know that fees have been payed, we need to not over
		// use compute on the ante handler

		// can we auth the fee payer with < 300 gas if we can, good, we have a fee payer
		// fees are not a problem, this can now be deduct from that account
		// but if not, we need to fail

		// if fee payer has complex authenticator that requires 800 gas, we fail straight away

		// multisig => 10 signatures to be verified => 100 per signature => 1000 gas
		// all 10 signature need to sign
		// we're > 300, but the first signature is valid

		// multisig => 10 signatures to be verified => 100 per signature => 1000 gas
		// all 10 signature need to sign
		// we're > 300, but the first signature is valid

		// fee payer set
		// set max gas 7000 && set max signers 7
		// set max gas 7000 => gas_limit
		// fee payer verified
		// sig 1 => correct
		// deduct gas
		// sig 2 => correct
		// deduct gas
		// sig 3 => correct
		// deduct gas
		// sig 4 => correct
		// deduct gas
		// fee payer is charged because of correct signature[0]

		// case statement on types

		for _, authenticator := range authenticators {
			// Get the authentication data for the transaction
			authData, err := authenticator.GetAuthenticationData(tx, uint8(msgIndex), simulate)

			// iterate again
			if err != nil {
				return ctx, err
			}

			fmt.Println(authData)
			fmt.Println(params)
			fmt.Println(sigTx)
			// 			Authenticate the message
			//			err = sgcd.sigGasConsumer(ctx.GasMeter(), authData.Signatures[0], params)
			//			if err != nil {
			//				return ctx, err
			//			}
		}

	}

	return next(ctx, tx, simulate)
}
