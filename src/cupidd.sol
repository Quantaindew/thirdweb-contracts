// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@anon-aadhaar/contracts/interfaces/IAnonAadhaar.sol";

contract AadhaarWalletRegistry {
    address public immutable anonAadhaarVerifierAddr;

    mapping(uint256 => bool) public hasRegistered;
    mapping(address => string) public walletMetadata;
    mapping(address => string) public walletGender;
    address[] public registeredWallets;

    struct WalletInfo {
        address walletAddress;
        string metadata;
        string gender;
    }

    event WalletRegistered(address indexed wallet, string gender);
    event MetadataUpdated(address indexed wallet, string newMetadata);

    constructor(address _verifierAddr) {
        anonAadhaarVerifierAddr = _verifierAddr;
    }

    function addressToUint256(address _addr) private pure returns (uint256) {
        return uint256(uint160(_addr));
    }

    function registerWallet(
        string memory metadataJsonKey, 
        string memory gender,
        uint nullifierSeed,
        uint nullifier,
        uint timestamp,
        uint signal,
        uint[4] memory revealArray,
        uint[8] memory groth16Proof
    ) public {
        require(addressToUint256(msg.sender) == signal, "Signal does not match sender");
        require(
            IAnonAadhaar(anonAadhaarVerifierAddr).verifyAnonAadhaarProof(
                nullifierSeed,
                nullifier,
                timestamp,
                signal,
                revealArray,
                groth16Proof
            ),
            "Invalid Aadhaar proof"
        );
        require(!hasRegistered[nullifier], "Aadhaar already registered");
        require(keccak256(bytes(gender)) == keccak256(bytes("77")) || keccak256(bytes(gender)) == keccak256(bytes("70")), "Invalid gender code");

        hasRegistered[nullifier] = true;
        walletMetadata[msg.sender] = metadataJsonKey;
        walletGender[msg.sender] = gender;
        registeredWallets.push(msg.sender);

        emit WalletRegistered(msg.sender, gender);
    }

    function updateMetadata(string memory newMetadataJsonKey) public {
        require(bytes(walletGender[msg.sender]).length != 0, "Wallet not registered");
        walletMetadata[msg.sender] = newMetadataJsonKey;
        emit MetadataUpdated(msg.sender, newMetadataJsonKey);
    }

    function getAllWalletInfo() public view returns (WalletInfo[] memory) {
        WalletInfo[] memory infos = new WalletInfo[](registeredWallets.length);
        for (uint i = 0; i < registeredWallets.length; i++) {
            address wallet = registeredWallets[i];
            infos[i] = WalletInfo(wallet, walletMetadata[wallet], walletGender[wallet]);
        }
        return infos;
    }

    function getRegisteredWalletsCount() public view returns (uint256) {
        return registeredWallets.length;
    }
}