#include "context.hpp"

#include <openfhe.h>

lbcrypto::CryptoContext<lbcrypto::DCRTPoly> generate_context() {

    // Selección de parámetros.

    // auto secretKeyDist = lbcrypto::SecretKeyDist::SPARSE_TERNARY;

    constexpr uint32_t scale_mod_size = 49;
    constexpr uint32_t first_mod = 52;
    constexpr uint32_t num_large_digits = 5;

    lbcrypto::CCParams<lbcrypto::CryptoContextCKKSRNS> parameters;
    parameters.SetScalingModSize(scale_mod_size);
	parameters.SetFirstModSize(first_mod);
    parameters.SetRingDim(ring_dim);
    parameters.SetBatchSize(num_slots); 
    parameters.SetSecurityLevel(lbcrypto::HEStd_NotSet);
    parameters.SetScalingTechnique(lbcrypto::FLEXIBLEAUTO);
    parameters.SetNumLargeDigits(num_large_digits);
    parameters.SetCKKSDataType(lbcrypto::COMPLEX);

    // Default secret key distribution.
    // parameters.SetSecretKeyDist(secretKeyDist);

    // Parámetros bootstrap.
    constexpr uint32_t levelsAvailableAfterBootstrap = 5;

    usint depth = levelsAvailableAfterBootstrap + lbcrypto::FHECKKSRNS::GetBootstrapDepth(level_budget, parameters.GetSecretKeyDist());
    parameters.SetMultiplicativeDepth(depth);

    std::cout << "Máxima profundidad multiplicativa: " << depth << std::endl;

    // Creación del contexto.

    const lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(lbcrypto::FHE);
    cc->Enable(lbcrypto::PKE);
    cc->Enable(lbcrypto::LEVELEDSHE);
    cc->Enable(lbcrypto::KEYSWITCH);
    cc->Enable(lbcrypto::ADVANCEDSHE);

    return cc;
}
