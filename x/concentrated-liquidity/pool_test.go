package concentrated_liquidity_test

import (
	fmt "fmt"

	sdk "github.com/cosmos/cosmos-sdk/types"

	cl "github.com/osmosis-labs/osmosis/v12/x/concentrated-liquidity"
	cltypes "github.com/osmosis-labs/osmosis/v12/x/concentrated-liquidity/types"
)

func (s *KeeperTestSuite) TestCalcOutAmtGivenIn() {
	ctx := s.Ctx
	pool, err := s.App.ConcentratedLiquidityKeeper.CreateNewConcentratedLiquidityPool(ctx, 1, "eth", "usdc", sdk.MustNewDecFromStr("70.710678"), sdk.NewInt(85176))
	s.Require().NoError(err)
	s.SetupPosition(pool.Id)

	// // test asset a to b logic
	// tokenIn := sdk.NewCoin("eth", sdk.NewInt(133700))
	// tokenOutDenom := "usdc"
	// swapFee := sdk.NewDec(0)
	minPrice := sdk.NewDec(4500)
	maxPrice := sdk.NewDec(5500)

	// _, amountOut, err := s.App.ConcentratedLiquidityKeeper.CalcOutAmtGivenIn(ctx, tokenIn, tokenOutDenom, swapFee, minPrice, maxPrice, pool.Id)
	// s.Require().NoError(err)
	// s.Require().Equal(sdk.NewDec(666975610).String(), amountOut.Amount.ToDec().String())

	// test asset b to a logic
	tokenIn := sdk.NewCoin("usdc", sdk.NewInt(4_199_999_999))
	tokenOutDenom := "eth"
	swapFee := sdk.NewDec(0)

	_, amountOut, err := s.App.ConcentratedLiquidityKeeper.CalcOutAmtGivenIn(ctx, tokenIn, tokenOutDenom, swapFee, minPrice, maxPrice, pool.Id)
	s.Require().NoError(err)
	s.Require().Equal(sdk.NewDec(805287), amountOut.Amount.ToDec())

	// test asset b to a logic
	// tokenIn := sdk.NewCoin("usdc", sdk.NewInt(42_000_000))
	// tokenOutDenom := "eth"
	// swapFee := sdk.NewDec(0)

	// _, amountOut, err := s.App.ConcentratedLiquidityKeeper.CalcOutAmtGivenIn(ctx, tokenIn, tokenOutDenom, swapFee, minPrice, maxPrice, pool.Id)
	// s.Require().NoError(err)
	// s.Require().Equal(sdk.NewDec(8396), amountOut.Amount.ToDec())

	// // test with swap fee
	// tokenzIn = sdk.NewCoin("usdc", sdk.NewInt(4199999999))
	// tokenOutDenom = "eth"
	// swapFee = sdk.NewDecWithPrec(2, 2)

	// _, amountOut, err = s.App.ConcentratedLiquidityKeeper.CalcOutAmtGivenIn(ctx, tokenIn, tokenOutDenom, swapFee, minPrice, maxPrice, pool.Id)
	// s.Require().NoError(err)
	// s.Require().Equal(sdk.NewDec(789834), amountOut.Amount.ToDec())
}

func (s *KeeperTestSuite) TestCalcInAmtGivenOut() {
	ctx := s.Ctx
	pool, err := s.App.ConcentratedLiquidityKeeper.CreateNewConcentratedLiquidityPool(s.Ctx, 1, "eth", "usdc", sdk.MustNewDecFromStr("70.710678"), sdk.NewInt(85176))
	s.Require().NoError(err)
	s.SetupPosition(pool.Id)

	// test asset a to b logic
	tokenOut := sdk.NewCoin("eth", sdk.NewInt(805287))
	tokenInDenom := "usdc"
	swapFee := sdk.NewDec(0)
	minPrice := sdk.NewDec(4500)
	maxPrice := sdk.NewDec(5500)

	amountIn, amountOut, err := s.App.ConcentratedLiquidityKeeper.CalcInAmtGivenOut(ctx, tokenOut, tokenInDenom, swapFee, minPrice, maxPrice, pool.Id)
	fmt.Println(amountIn.String())
	fmt.Println(amountOut.String())
	s.Require().NoError(err)
	s.Require().Equal(sdk.NewDec(4_199_999_999), amountIn.Amount.ToDec())

	// // test asset b to a logic
	// tokenOut = sdk.NewCoin("eth", sdk.NewInt(133700))
	// tokenInDenom = "usdc"
	// swapFee = sdk.NewDec(0)

	// amountIn, _, err = s.App.ConcentratedLiquidityKeeper.CalcInAmtGivenOut(ctx, tokenOut, tokenInDenom, swapFee, minPrice, maxPrice, pool.Id)
	// s.Require().NoError(err)
	// s.Require().Equal(sdk.NewDec(666975610), amountIn.Amount.ToDec())

	// // test asset a to b logic
	// tokenOut = sdk.NewCoin("usdc", sdk.NewInt(4199999999))
	// tokenInDenom = "eth"
	// swapFee = sdk.NewDecWithPrec(2, 2)

	// amountIn, _, err = s.App.ConcentratedLiquidityKeeper.CalcInAmtGivenOut(ctx, tokenOut, tokenInDenom, swapFee, minPrice, maxPrice, pool.Id)
	// s.Require().NoError(err)
	// s.Require().Equal(sdk.NewDec(821722), amountIn.Amount.ToDec())
}

func (s *KeeperTestSuite) TestOrderInitialPoolDenoms() {
	denom0, denom1, err := cltypes.OrderInitialPoolDenoms("axel", "osmo")
	s.Require().NoError(err)
	s.Require().Equal(denom0, "axel")
	s.Require().Equal(denom1, "osmo")

	denom0, denom1, err = cltypes.OrderInitialPoolDenoms("usdc", "eth")
	s.Require().NoError(err)
	s.Require().Equal(denom0, "eth")
	s.Require().Equal(denom1, "usdc")

	denom0, denom1, err = cltypes.OrderInitialPoolDenoms("usdc", "usdc")
	s.Require().Error(err)

}

func (suite *KeeperTestSuite) TestPriceToTick() {
	testCases := []struct {
		name         string
		price        sdk.Dec
		tickExpected string
	}{
		{
			"happy path",
			sdk.NewDec(5000),
			"85176",
		},
	}

	for _, tc := range testCases {
		tc := tc

		suite.Run(tc.name, func() {
			tick := cl.PriceToTick(tc.price)
			suite.Require().Equal(tc.tickExpected, tick.String())
		})
	}
}
