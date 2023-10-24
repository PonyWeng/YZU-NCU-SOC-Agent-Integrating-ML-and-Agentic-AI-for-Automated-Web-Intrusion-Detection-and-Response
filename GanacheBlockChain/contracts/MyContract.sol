// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MyContract {
    address public owner;
    string[] public logs;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only the owner can call this function");
        _;
    }

    function addLog(string memory logEntry) public onlyOwner {
        logs.push(logEntry);
    }

    function getLogsCount() public view returns (uint) {
        return logs.length;
    }

    function getLog(uint index) public view returns (string memory) {
        require(index < logs.length, "Index out of bounds");
        return logs[index];
    }
}
