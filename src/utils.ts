import BigNumber from 'bignumber.js'

export const TunedBigNumber = BigNumber.clone({
	EXPONENTIAL_AT: 1e9,
	DECIMAL_PLACES: 36, // MNano Zeroes
})
