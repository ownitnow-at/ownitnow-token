# Universal Real Estate Token

UREToken is an upgradable ERC-20 token built with OpenZeppelin libraries. It includes features such as role-based minting&burning, pausing, and user blocklisting. This token is suitable for applications requiring fine-grained control over token transferability and governance.

## ✨ Features

- ✅ ERC-20 compliant with configurable decimals
- 🔒 Role-based access control for minting, burning, pausing, and freezing
- 🔥 Burnable (by authorized roles only for own funds or allowed funds)
- ⏸️ Pausable transfers
- 🚫 Blocklisting of malicious or frozen accounts
- 🧾 Permit (EIP-2612) support for gasless approvals
- 🧬 Fully upgradeable (via OpenZeppelin's proxy upgrade pattern)

## 🚀 Deployment

Note: The deployer wallet automatically gets admin role and can upgrade the contract.  

### Initialization Parameters

| Parameter       | Description                         |
|-----------------|-------------------------------------|
| `tokenName`     | The name of the token               |
| `tokenSymbol`   | The symbol (e.g., `URE`)            |
| `tokenDecimals` | Number of decimal places (e.g., 18) |

### Example

```solidity
UREToken.initialize("URE Token", "URE", 8);
```

### Foundry Deployment

Copy .env.sample file to .env and enter all values you need.  
Note: in some cases, e.g. when deploying with ledger, foundry uses the default value for sender. This results
in the situation that the owner of the admin contract is set to the default value which means the contract 
can't be upgrade later, because of missing owner rights. Therefore, `--sender <0xOwnerAddress>` is used in 
the following sample deployment commands:

```bash
source .env
# Deploy to Ethereum Sepolia using keystores and custom optimizer-runs + verify contract
forge script script/DeployToken.s.sol:DeployToken --keystore keystores/deployer --broadcast --slow --verify --rpc-url $ETH_SEPOLIA_RPC --etherscan-api-key $ETHERSCAN_API_KEY --sender $DEPLOYER  --optimizer-runs 10000

# Deploy to Avalanche Fuji with private key + verify contracts
forge script script/DeployToken.s.sol:DeployToken --private-key $DEPLOYER_KEY --broadcast --optimize --slow --verify --rpc-url $AVALANCHE_FUJI_RPC --etherscan-api-key $ETHERSCAN_API_KEY --verifier-url $AVALANCHE_FUJI_VERIFIER_URL --sender $DEPLOYER
```

## 🔐 Roles

| Role                 | Description                                     |
| -------------------- | ----------------------------------------------- |
| `DEFAULT_ADMIN_ROLE` | Admin role for managing other roles             |
| `MINTER_ROLE`        | Can mint and burn own and tokens with allowance |
| `PAUSER_ROLE`        | Can pause and unpause transfers                 |
| `FREEZER_ROLE`       | Can block and unblock users                     |

## Foundry Commands

```bash
# build
forge build

# run tests
forge test

# format code 
forge fmt

# get gas report
forge test --gas-report --optimizer-runs 10000

# run static code analysis
slither .
```
