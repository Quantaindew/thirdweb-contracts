// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@anon-aadhaar/contracts/interfaces/IAnonAadhaar.sol";

contract MyContract is Ownable {
    mapping(string => address) public registeredAddresses;
    mapping(address => string) public walletMetadata;
    mapping(address => string) public walletGender;
    address[] public allRegisteredAddresses;
    mapping(uint256 => bool) public hasRegistered;

    address public anonAadhaarVerifierAddr;

    struct WalletInfo {
        address walletAddress;
        string metadata;
        string gender;
    }

    constructor(address initialOwner, address _verifierAddr) Ownable(initialOwner) {
        anonAadhaarVerifierAddr = _verifierAddr;
    }

    function addressToUint256(address _addr) private pure returns (uint256) {
        return uint256(uint160(_addr));
    }

    function registerAddress(
        string memory identifier, 
        address addr, 
        string memory metadataJsonKey, 
        string memory gender,
        uint nullifierSeed,
        uint nullifier,
        uint timestamp,
        uint signal,
        uint[4] memory revealArray,
        uint[8] memory groth16Proof
    ) public {
        require(addressToUint256(msg.sender) == signal, "Signal does not match msg.sender");
        require(
            IAnonAadhaar(anonAadhaarVerifierAddr).verifyAnonAadhaarProof(
                nullifierSeed,
                nullifier,
                timestamp,
                signal,
                revealArray,
                groth16Proof
            ),
            "Invalid proof"
        );
        require(!hasRegistered[nullifier], "Already registered");
        require(registeredAddresses[identifier] == address(0), "Identifier already used");
        require(keccak256(bytes(gender)) == keccak256(bytes("77")) || keccak256(bytes(gender)) == keccak256(bytes("70")), "Invalid gender code");

        registeredAddresses[identifier] = addr;
        walletMetadata[addr] = metadataJsonKey;
        walletGender[addr] = gender;
        allRegisteredAddresses.push(addr);
        hasRegistered[nullifier] = true;
    }

    function getAllWalletInfo() public view returns (WalletInfo[] memory) {
        WalletInfo[] memory infos = new WalletInfo[](allRegisteredAddresses.length);
        for (uint i = 0; i < allRegisteredAddresses.length; i++) {
            infos[i].walletAddress = allRegisteredAddresses[i];
            infos[i].metadata = walletMetadata[allRegisteredAddresses[i]];
            infos[i].gender = walletGender[allRegisteredAddresses[i]];
        }
        return infos;
    }

    function updateMetadata(address addr, string memory newMetadataJsonKey) public {
        require(msg.sender == owner() || msg.sender == addr, "Not authorized");
        walletMetadata[addr] = newMetadataJsonKey;
    }
}