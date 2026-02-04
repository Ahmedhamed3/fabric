export PATH=/opt/fabric-dev/bin:$PATH
export FABRIC_CFG_PATH=/opt/fabric-dev/config
export CORE_PEER_TLS_ENABLED=true
export CORE_PEER_LOCALMSPID=Org1MSP
export CORE_PEER_ADDRESS=peer0.org1.example.com:7051
export CORE_PEER_MSPCONFIGPATH=/opt/fabric-dev/socnet/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
export CORE_PEER_TLS_ROOTCERT_FILE=/opt/fabric-dev/socnet/crypto-config/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
export ORDERER_CA=/opt/fabric-dev/socnet/crypto-config/ordererOrganizations/example.com/orderers/orderer.example.com/tls/ca.crt
