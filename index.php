<?php

	require_once('/var/www/core/database.php');

	class server{
	
		private $db;
		private $hex_iv = '00000000000000000000000000000000';
	
		public function __construct(){
		
			$this->db = new database();
		
		}
		
		public function run(){
		
			if(!isset($_POST['action'])) $this->error();
			
			switch($_POST['action']){
			
				case 'requestPG':
					
					$p = rand(281474976710656,1125899906842624); //zahl zwischen Unsigned INT 48Bit und 50Bit
					$p = gmp_nextprime($p);
					
					$g = 2;
					$secretRandom = rand(1,gmp_intval($p)-1);
					
					$sessionID = md5(uniqid());
					
					$publicKey = gmp_powm($g,$secretRandom,$p);
					$publicKey = gmp_strval($publicKey);

					$this->db->prepare("INSERT INTO Session (Session_ID,p,g,Secret_Random,Server_Public_Key) VALUES (:Session_ID,:p,:g,:Secret_Random,:Server_Public_Key)");
					$this->db->bind(array(
						'Session_ID' => $sessionID,
						'p' => gmp_strval($p),
						'g' => $g,
						'Secret_Random' => $secretRandom,
						'Server_Public_Key' => $publicKey				
					));
					
					if($this->db->execute()){
					
						exit(json_encode(array('sessionID' => $sessionID, 'p' => gmp_strval($p), 'g' => $g, 'serverPublicKey' => $publicKey)));
						
					}
					
				case 'handshake':
				
					$this->db->prepare("SELECT p,Secret_Random FROM Session WHERE Session_ID = :Session_ID");
					$this->db->bind(array('Session_ID' => $_POST['sessionID']));
					$sessionData = $this->db->fetchAssoc();
					if(empty($sessionData)) error();

					$privateKey = gmp_powm($_POST['publicKey'],$sessionData[0]['Secret_Random'],$sessionData[0]['p']);
					$privateKey = gmp_strval($privateKey);
					
					$this->db->prepare("UPDATE Session SET Client_Public_Key = :publicKey, Private_Key = :privateKey WHERE Session_ID = :Session_ID");
					$this->db->bind(array('publicKey' => $_POST['publicKey'], 'privateKey' => $privateKey, 'Session_ID' => $_POST['sessionID']));
					if($this->db->execute()){
					
						exit(json_encode(array('handshakeStatus' => 'OK')));
					
					}
					
				case 'secureCom':
					
					$this->db->prepare("SELECT Private_Key FROM Session WHERE Session_ID = :sessionID");
					$this->db->bind(array('sessionID' => $_POST['sessionID']));
					$session = $this->db->fetchAssoc();
					if(empty($session)) error();
										
					$payload = $this->decrypt($_POST['payload'], hash('sha256', $session[0]['Private_Key'], true));
					
					$payload = json_decode($payload, true);
					
					switch($payload['action']){
					
						case 'find':
												
							if(empty($payload['long']) || empty($_POST['payload'])){
							
								$this->secureCom(json_encode(array('status' => false)), hash('sha256', $session[0]['Private_Key'], true));
							
							}else{
							
								$this->secureCom(json_encode(array('status' => true)), hash('sha256', $session[0]['Private_Key'], true));
							
							}
							break;
					
						default:
				
							$this->error();
							break;
					
					}

					break;
					
			
				default:
				
					$this->error();
					break;
			
			}
		
		}
		
		private function secureCom($payload, $key){
		
			exit($this->encrypt($payload, $key));
		
		}

		private function error(){

			header($_SERVER['SERVER_PROTOCOL'] . ' 500 Internal Server Error', true, 500);
			exit();
		
		}
		
		private function hexToStr($hex)
		{
			$string='';
			for ($i=0; $i < strlen($hex)-1; $i+=2)
			{
				$string .= chr(hexdec($hex[$i].$hex[$i+1]));
			}
			return $string;
		}
		
		private function encrypt($value, $key){       
					
			$td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
			mcrypt_generic_init($td, $key, $this->hexToStr($this->hex_iv));
			$block = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
			$pad = $block - (strlen($value) % $block);
			$value .= str_repeat(chr($pad), $pad);
			$encrypted = mcrypt_generic($td, $value);
			mcrypt_generic_deinit($td);
			mcrypt_module_close($td);        
			return base64_encode($encrypted);
		}
		
		private function decrypt($value, $key){   
		
			$td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
			mcrypt_generic_init($td, $key, $this->hexToStr($this->hex_iv));
			$str = mdecrypt_generic($td, base64_decode($value));
			$block = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
			mcrypt_generic_deinit($td);
			mcrypt_module_close($td);        
			return $this->strippadding($str);     
			
		}

		private function strippadding($string){
		
			$slast = ord(substr($string, -1));
			$slastc = chr($slast);
			$pcheck = substr($string, -$slast);
			if (preg_match("/$slastc{" . $slast . "}/", $string)) {
				$string = substr($string, 0, strlen($string) - $slast);
				return $string;
			} else {
				return false;
			}
			
		}
	
	}
	
	$server = new server();
	$server->run();
 
?>
