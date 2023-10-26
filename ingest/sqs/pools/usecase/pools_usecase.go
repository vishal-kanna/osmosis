package usecase

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/osmosis-labs/osmosis/v20/ingest/sqs/domain"
)

type poolsUseCase struct {
	contextTimeout  time.Duration
	poolsRepository domain.PoolsRepository
}

// NewPoolsUsecase will create a new pools use case object
func NewPoolsUsecase(timeout time.Duration, poolsRepository domain.PoolsRepository) domain.PoolsUsecase {
	return &poolsUseCase{
		contextTimeout:  timeout,
		poolsRepository: poolsRepository,
	}
}

// GetAllPools returns all pools from the repository.
func (a *poolsUseCase) GetAllPools(ctx context.Context) ([]domain.PoolI, error) {
	ctx, cancel := context.WithTimeout(ctx, a.contextTimeout)
	defer cancel()

	fmt.Println("CFMM")

	cfmmPools, err := a.poolsRepository.GetAllCFMM(ctx)
	if err != nil {
		return nil, err
	}

	fmt.Println("CL")

	concentratedPools, err := a.poolsRepository.GetAllConcentrated(ctx)
	if err != nil {
		return nil, err
	}

	fmt.Println("CW")

	cosmWasmPools, err := a.poolsRepository.GetAllCosmWasm(ctx)
	if err != nil {
		return nil, err
	}

	allPools := make([]domain.PoolI, 0, len(cfmmPools)+len(concentratedPools)+len(cosmWasmPools))
	allPools = append(allPools, cfmmPools...)
	allPools = append(allPools, concentratedPools...)
	allPools = append(allPools, cosmWasmPools...)

	// Sort by ID
	sort.Slice(allPools, func(i, j int) bool {
		return allPools[i].GetId() < allPools[j].GetId()
	})

	return allPools, nil
}