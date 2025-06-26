// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

import {Script, console} from "lib/forge-std/src/Script.sol";
import {OWNIT0Token} from "../src/OWNIT0Token.sol";
import {Upgrades} from "@openzeppelin-foundry-upgrades/Upgrades.sol";

/**
 * @title Deployment script for the URE token contract
 * @dev Upgradable ERC 20 contract.
 */
contract DeployToken is Script {
    OWNIT0Token public token;

    function run() public returns (OWNIT0Token) {
        vm.startBroadcast();

        string memory tokenName = vm.envString("TOKEN_NAME");
        string memory tokenSymbol = vm.envString("TOKEN_SYMBOL");
        uint8 tokenDecimals = uint8(vm.envUint("TOKEN_DECIMALS"));

        console.log("Deploy transparent proxy");
        address proxyAddress = Upgrades.deployTransparentProxy(
            "OWNIT0Token.sol",
            msg.sender,
            abi.encodeCall(OWNIT0Token.initialize, (tokenName, tokenSymbol, tokenDecimals))
        );

        token = OWNIT0Token(proxyAddress);

        console.log("OWNIT0Token deployed at:", proxyAddress);
        address implementationAddress = Upgrades.getImplementationAddress(proxyAddress);
        console.log("Implementation address:", implementationAddress);

        vm.stopBroadcast();

        return token;
    }
}
