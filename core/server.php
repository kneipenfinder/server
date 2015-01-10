<?php

	class server{
	
		private $db;
		private $hex_iv = '00000000000000000000000000000000';
		private $limb_limiter = 8;
	
		public function __construct(){
		
			$this->db = new database();
		
		}
		
		public function run(){

			if(!isset($_POST['action'])) $this->error();
			
			switch($_POST['action']){
			
				case 'requestPG':
					
					$p = gmp_random($this->limb_limiter);
					$p = gmp_nextprime($p);
					$g = 2;
					
					$secretRandom = $p;
					while(gmp_cmp($secretRandom, $p) >= 0){
					
						// Endlosschleife theoretisch möglich, aber praktisch "unmöglich"
						$secretRandom = gmp_random($this->limb_limiter);
					
					}

					$sessionID = md5(uniqid());
					
					$publicKey = gmp_powm($g,$secretRandom,$p);
					$publicKey = gmp_strval($publicKey);

					$this->db->prepare("INSERT INTO Session (Session_ID,p,g,Secret_Random,Server_Public_Key) VALUES (:Session_ID,:p,:g,:Secret_Random,:Server_Public_Key)");
					$this->db->bind(array(
						'Session_ID' => $sessionID,
						'p' => gmp_strval($p),
						'g' => $g,
						'Secret_Random' => gmp_strval($secretRandom),
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
												
							if(empty($payload['long']) || empty($payload['lat'])){
							
								$this->secureCom(json_encode(array('status' => false)), hash('sha256', $session[0]['Private_Key'], true));
							
							}else{
							
								$locations = $this->getLocations($payload['lat'], $payload['long']);
							
								$this->secureCom(json_encode(array('status' => true, 'locations' => $locations)), hash('sha256', $session[0]['Private_Key'], true));
							
							}
							break;
							
						case 'add':
						
								$name = $payload['name'];
								$long = $payload['long'];
								$lat = $payload['lat'];
								$street = $payload['street'];
								$postcode = $payload['postcode'];
								$type = $payload['type'];
								
								$this->db->prepare("SELECT Postcode_ID FROM ".TABLE_POSTCODE." WHERE Postcode = :postcode");
								$this->db->bind(array('postcode' => $postcode));
								$postcode = $this->db->fetchAssoc();
								if(empty($postcode)){

									$this->secureCom(json_encode(array('status' => false, 'msg' => 'Die eingegebene Postleitzahl existiert nicht.')), hash('sha256', $session[0]['Private_Key'], true));									
								
								}
								
								// $typenum=0;
								// $this->db->prepare("SELECT Location_Type_ID FROM Location_Type WHERE Bezeichnung = :type");
								// $this->db->bind(array('type' => $type));
								// $typenum = $this->db->fetchAssoc();								
								
								$this->db->prepare("INSERT INTO ".TABLE_LOCATION." (Location_Type_ID, Location_Name, Longitude, Latitude, Strasse, Postcode_ID, enabled) VALUES (:type, :name, :long, :lat, :street, :postcode, 0)");
								$this->db->bind(array(
									'type' => 1,
									'name' => $name,
									'long' => $long,
									'lat' => $lat,
									'street' => $street,
									'postcode' => $postcode[0]['Postcode_ID']
								));

								$this->secureCom(json_encode(array('status' => $this->db->execute())), hash('sha256', $session[0]['Private_Key'], true));

								
							break;
							
						case 'getLocationTypes':
						
							$this->db->prepare("SELECT Location_Type_ID AS id, Bezeichnung AS name FROM ".TABLE_LOCATION_TYPE);
							$locationTypes = $this->db->fetchAssoc();
							if(empty($locationTypes)){
							
								$this->secureCom(json_encode(array('status' => false)), hash('sha256', $session[0]['Private_Key'], true));
							
							}else{
							
								$this->secureCom(json_encode(array('status' => true, 'locationTypes' => $locationTypes)), hash('sha256', $session[0]['Private_Key'], true));
							
							}
							
							break;
							
						case 'getLocationDetails':
							
							$locationID = $payload['LocationID'];
							$latitude = $payload['lat'];
							$longitude = $payload['long'];

							if(empty($locationID)){
							
								$this->secureCom(json_encode(array('status' => false)), hash('sha256', $session[0]['Private_Key'], true));
							
							}else{
							
								$location = $this->getLocationByID($locationID, $latitude, $longitude);
								if($location === false){
								
									$status = false;
								
								}else{
								
									$status = true;
								
								}
								$this->secureCom(json_encode(array('status' => $status, 'location' => $location)), hash('sha256', $session[0]['Private_Key'], true));
							}
							
							break;
							
						case 'getLocationPictures':
							
							$locationID = $payload['LocationID'];
							
							if(empty($locationID)){
							
								$this->secureCom(json_encode(array('status' => false)), hash('sha256', $session[0]['Private_Key'], true));
							
							} else{
							
								$pictures = $this->getLocationPics($locationID);
								$this->secureCom(json_encode(array('status' => true, 'pictures' => $pictures)), hash('sha256', $session[0]['Private_Key'], true));
							
							}
							
							 break;
					
						default:
				
							$this->error();
							break;
					
					}

					break;
					
				case 'webCon':
				
					if(!isset($_POST['type'])) $this->error();
			
					switch($_POST['type']){
					
						case 'find':
						
							if(empty($_POST['long']) || empty($_POST['lat'])){
							
								exit(json_encode(array('status' => false, 'msg' => 'Lat / Long nicht übergeben.')));
							
							}else{
						
								$locations = $this->getLocations($_POST['lat'], $_POST['long'], $_POST['limit'], $_POST['offset']);
								exit(json_encode(array('status' => true, 'locations' => $locations)));
								
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
		
		public function getLocationById($locationID, $lat = null, $long = null){
		
			$this->db->prepare("SELECT a.Location_Name, c.District, a.Strasse, a.Longitude, a.Latitude, a.Sky_Sport, a.Biergarten, a. Open_From_Monday, a.Open_To_Monday, a. Open_From_Tuesday, a.Open_To_Tuesday, a. Open_From_Wednesday, a.Open_To_Wednesday, a. Open_From_Thursday, a.Open_To_Thursday, a. Open_From_Friday, a.Open_To_Friday, a. Open_From_Saturday, a.Open_To_Saturday, a. Open_From_Sunday, a.Open_To_Sunday, b.Bezeichnung, c.Postcode, d.City_Name FROM ".TABLE_LOCATION." a INNER JOIN ".TABLE_LOCATION_TYPE." b ON a.Location_Type_ID = b.Location_Type_ID INNER JOIN ".TABLE_POSTCODE." c ON c.Postcode_ID = a.Postcode_ID INNER JOIN ".TABLE_CITY." d ON d.City_ID = c.City_ID WHERE a.Location_ID = :locationID");
			$this->db->bind(array('locationID' => $locationID));
			$result = $this->db->fetchAssoc();

			if(empty($result)) return false;
			$result = $result[0];
			
			$distance = $this->getDistance($result['Latitude'],$result['Longitude'],$lat,$long);
			$orientation = $this->getOrientation($lat,$long,$result['Latitude'],$result['Longitude']);
			
			$this->db->prepare("SELECT AVG(Number_Of_Stars) AS stars, COUNT(Location_Rating_ID) AS amount FROM ".TABLE_LOCATION_RATING." WHERE Location_ID = :id");
			$this->db->bind(array('id' => $locationID));
			$rating = $this->db->fetchAssoc();
			$rating_stars = 0;
			$rating_amount = 0;
			if(!empty($rating)){
				
				$rating_stars = $rating[0]['stars'];
				$rating_amount = $rating[0]['amount'];
				
			}
			
			$comments = $this->getComments($locationID);
	
			$location = array('name' => $result['Location_Name'], 'strasse' => $result['Strasse'], 'sky_sport' => $result['Sky_Sport'], 'biergarten' => $result['Biergarten'], 'Open_From_Monday' => $result['Open_From_Monday'], 'Open_To_Monday' => $result['Open_To_Monday'], 'Open_From_Tuesday' => $result['Open_From_Tuesday'], 'Open_To_Tuesday' => $result['Open_To_Tuesday'], 'Open_From_Wednesday' => $result['Open_From_Wednesday'],'Open_To_Wednesday' => $result['Open_To_Wednesday'], 'Open_From_Thursday' => $result['Open_From_Thursday'], 'Open_To_Thursday' => $result['Open_To_Thursday'], 'Open_From_Friday' => $result['Open_From_Friday'], 'Open_To_Friday' => $result['Open_To_Friday'], 'Open_From_Saturday' => $result['Open_From_Saturday'], 'Open_To_Saturday' => $result['Open_To_Saturday'], 'Open_From_Sunday' => $result['Open_From_Sunday'],'Open_To_Sunday' => $result['Open_To_Sunday'], 'distance' => $distance, 'orientation' => $orientation, 'rating_amount' => $rating_amount, 'rating_stars' => $rating_stars, 'comments' => $comments, 'postcode' => $result['Postcode'], 'city' => $result['City_Name'], 'district' => $result['District']);
			
			return $location;
			
		}
		
		private function getComments($locationID){
		
			$this->db->prepare("SELECT Optional_Comment FROM ".TABLE_LOCATION_RATING." 
			WHERE Location_ID = :ID");
			$this->db->bind(array('ID' => $locationID));
			$comments = $this->db->fetchAssoc();
			return $comments;
			
		}
		
		private function getLocationPics($locationID){
		
			$this->db->prepare("SELECT Filename FROM ".TABLE_LOCATION_PICTURES."
			WHERE Location_ID = :ID");
			$this->db->bind(array('ID' => $locationID));
			$pictures = $this->db->fetchAssoc();
			return $pictures;
			
		}
		
		private function getLocations($lat, $long, $limit = 10, $offset = 0){
		
			$this->db->prepare("SELECT a.Location_Name,a.Location_ID,a.Longitude,a.Latitude,a.Strasse,b.Bezeichnung,c.Postcode,c.District,d.City_Name FROM ".TABLE_LOCATION." a INNER JOIN ".TABLE_LOCATION_TYPE." b ON a.Location_Type_ID = b.Location_Type_ID INNER JOIN ".TABLE_POSTCODE." c ON a.Postcode_ID = c.Postcode_ID INNER JOIN ".TABLE_CITY." d ON c.City_ID = d.City_ID WHERE enabled = 1");
			$results = $this->db->fetchAssoc();
			$locations = array();
			if(!empty($results)){
			
				foreach($results as $result){
				
					$distance = $this->getDistance($result['Latitude'],$result['Longitude'],$lat,$long);
					$orientation = $this->getOrientation($lat,$long,$result['Latitude'],$result['Longitude']);
					
					$this->db->prepare("SELECT AVG(Number_Of_Stars) AS stars, COUNT(Location_Rating_ID) AS amount FROM ".TABLE_LOCATION_RATING." WHERE Location_ID = :id");
					$this->db->bind(array('id' => $result['Location_ID']));
					$rating = $this->db->fetchAssoc();
					$rating_stars = 0;
					$rating_amount = 0;
					if(!empty($rating)){
						
						$rating_stars = $rating[0]['stars'];
						$rating_amount = $rating[0]['amount'];
						
					}
					
					$locations[] = array('id' => $result['Location_ID'], 'name' => $result['Location_Name'], 'lat' => $result['Latitude'], 'long' => $result['Longitude'], 'street' => $result['Strasse'], 'distance' => $distance, 'orientation' => $orientation, 'type' => $result['Bezeichnung'], 'postcode' => $result['Postcode'], 'city' => $result['City_Name'], 'district' => $result['District'], 'rating_amount' => $rating_amount, 'rating_stars' => $rating_stars);
				
				}
			
			}
			
			

			return array_slice($this->sortArrayByChildArrayKey($locations, 'distance'), $offset, $limit);

		}
		
		private function sortArrayByChildArrayKey($array, $sortBy, $order = SORT_ASC){
		
			$sort = array();
			foreach($array as $key => $value){
			
			  $sort[$key]  = $value[$sortBy];
			  
			}
			array_multisort($sort, $order, $array);
			return $array;
		
		}
		
		private function getOrientation($fromLat,$fromLong,$toLat,$toLong){
			
			$diffLong = $toLong-$fromLong;
			$diffLat = $toLat-$fromLat;
			$s =  atan2($diffLong, $diffLat) * 180 / pi();
			$orientation = '';
			if($s > -22.5 && $s <= 22.5){
				$orientation = 'N';
			}elseif($s > 22.5 && $s <= 72.5){
				$orientation = 'NE';
			}elseif($s > 72.5 && $s <= 122.5){
				$orientation = 'E';
			}elseif($s > 122.5 && $s <= 172.5){
				$orientation = 'SE';
			}elseif($s > 172.5 && $s <= 180){
				$orientation = 'S';
			}elseif($s >= -180 && $s <= -172.5){
				$orientation = 'S';
			}
			elseif($s > -172.5 && $s <= -122.5){
				$orientation = 'SW';
			}elseif($s > -122.5 && $s <= -72.5){
				$orientation = 'W';
			}elseif($s > -72.5 && $s <= -22.5){
				$orientation = 'NW';
			}
			return $orientation;
		
		}
		
		private function getDistance($lat1,$long1,$lat2,$long2){

			$delta = $long1 - $long2;
			$distance = sin(deg2rad($lat1)) * sin(deg2rad($lat2)) +  cos(deg2rad($lat1)) * cos(deg2rad($lat2)) * cos(deg2rad($delta));
			$distance = acos($distance);
			$distance = rad2deg($distance);
			$distance = round((($distance * 60 * 1852)/1000),1);
			return $distance;
		
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

?>
