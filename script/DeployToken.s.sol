// SPDX-License-Identifier: MIT
pragma solidity 0.8.27;

import {Script, console} from "lib/forge-std/src/Script.sol";
import {UREToken} from "../src/UREToken.sol";
import {Upgrades} from "@openzeppelin-foundry-upgrades/Upgrades.sol";

/**
 * @title Deployment script for the URE token contract
 * @dev Upgradable ERC 20 contract.
 */
contract DeployToken is Script {
    UREToken public token;

    function run() public returns (UREToken) {
        vm.startBroadcast();

        string memory tokenName = vm.envString("TOKEN_NAME");
        string memory tokenSymbol = vm.envString("TOKEN_SYMBOL");
        uint8 tokenDecimals = uint8(vm.envUint("TOKEN_DECIMALS"));

        console.log("Deploy transparent proxy");
        address proxyAddress = Upgrades.deployTransparentProxy(
            "UREToken.sol", msg.sender, abi.encodeCall(UREToken.initialize, (tokenName, tokenSymbol, tokenDecimals))
        );

        token = UREToken(proxyAddress);

        console.log("UREToken deployed at:", proxyAddress);
        address implementationAddress = Upgrades.getImplementationAddress(proxyAddress);
        console.log("Implementation address:", implementationAddress);

        vm.stopBroadcast();

        return token;
    }
}
