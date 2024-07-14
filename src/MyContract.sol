// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/access/Ownable.sol";
import "@anon-aadhaar/contracts/interfaces/IAnonAadhaar.sol";

contract MyContract is Ownable {
    mapping(string => address) public registeredAddresses;
    mapping(address => string) public walletMetadata;
    mapping(address => string) public walletGender;
    address[] public allRegisteredAddresses;

    struct WalletInfo {
        address walletAddress;
        string metadata;
        string gender;
    }

    constructor(address initialOwner) Ownable(initialOwner) {
    }

    // Function to convert msg.sender to uint256
    function addressToUint256(address _addr) private pure returns (uint256) {
        return uint256(uint160(_addr));
    }

    // Modified function to register an address with a unique identifier, metadata JSON key, and gender
    function registerAddress(string memory identifier, address addr, string memory metadataJsonKey, string memory gender, uint256 signal) public {
        // Verify msg.sender against signal
        require(addressToUint256(msg.sender) == signal, "Signal does not match msg.sender");

        require(registeredAddresses[identifier] == address(0), "Identifier already used");
        require(keccak256(bytes(gender)) == keccak256(bytes("77")) || keccak256(bytes(gender)) == keccak256(bytes("70")), "Invalid gender code");
        registeredAddresses[identifier] = addr;
        walletMetadata[addr] = metadataJsonKey;
        walletGender[addr] = gender;
        allRegisteredAddresses.push(addr); // Keep track of the registered address
    }

    // Function to get all wallet addresses with their metadata and gender
    function getAllWalletInfo() public view returns (WalletInfo[] memory) {
        WalletInfo[] memory infos = new WalletInfo[](allRegisteredAddresses.length);
        for (uint i = 0; i < allRegisteredAddresses.length; i++) {
            infos[i].walletAddress = allRegisteredAddresses[i];
            infos[i].metadata = walletMetadata[allRegisteredAddresses[i]];
            infos[i].gender = walletGender[allRegisteredAddresses[i]];
        }
        return infos;
    }

    // Function to update metadata JSON key for a wallet address
    function updateMetadata(address addr, string memory newMetadataJsonKey) public {
        require(msg.sender == owner() || msg.sender == addr, "Not authorized");
        walletMetadata[addr] = newMetadataJsonKey;
    }
}