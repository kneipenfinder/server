<?php

class database{

	// Speicher f�r Datenbank-Verbindungs Object
	private static $DB_Handler;
	// Speicher f�r Prepared Statement Object
	private static $ST_Handler;
	
	private static $connected = false;
	
	public function __construct(){
	
		if(!self::$connected){
		
			self::connect(SQL_HOST, SQL_DATABASE, SQL_USER, SQL_PASSWORD);
			self::$connected = true;
		
		}
		
	}
	
	// Erstelle DSN aus �bergebenen Daten und verbinde zur Datenbank	
	public static function connect($host,$dbname,$user,$pass){
	
		if(class_exists('PDO')){
		
			if(in_array('mysql', PDO::getAvailableDrivers())){
			
				$dsn = 'mysql:host='.$host.';dbname='.$dbname;
				try {
				
					self::$DB_Handler = new PDO($dsn, $user, $pass);
					self::$DB_Handler->query("SET CHARACTER SET utf8");
					self::$DB_Handler->query("SET NAMES 'utf8' COLLATE 'utf8_general_ci'");
					return true;
					
				}
				catch(PDOException $e) {
				
					print_r($e);
					exit();
				}
				
			}else{
			
				exit('PDO Datenbank Treiber ist nicht installiert.');
				
			}
			
		}else{
		
			exit('PDO Klasse nicht gefunden.');
			
		}
		
	}
	// Trenne die Verbindung
	public static function disconnect() {
	
		self::$DB_Handler = null;
		return true;
		
	}	
	
	public function beginTransaction(){
	
		return self::$DB_Handler->beginTransaction();
	
	}
	
	public function commit(){
	
		return self::$DB_Handler->commit();
	
	}
	
	// F�hre Statement aus und gebe die Zahl der betroffenen Zeilen zur�ck
	public static function execStatement($statement) {
	
		try{
		
			$count = self::$DB_Handler->exec($statement);
			if($count !== false) return $count;
			
		}catch(PDOException $e) {
		
			exit();
			
		}
		return false;
		
	}
	// Setzte prepared Statement
	public static function prepare($query) {
	
		try {
		
			self::$ST_Handler = self::$DB_Handler->prepare($query);
			return self::$ST_Handler;
			
		}
		catch(PDOException $e) {
		
			exit();
			
		}
	}	
	// Ersetzte im prepared Statement Object die �bergebenen Werte
	public static function bind(array $data) {
	
		if(is_array($data) && count($data) >= 1) {
		
			foreach($data as $key => $val) {
			
				switch(true) {
				
					case is_int($val):
						$type = PDO::PARAM_INT;
						break;

					case is_bool($val):
						$type = PDO::PARAM_BOOL;
						break;

					case is_null($val):
						$type = PDO::PARAM_NULL;
						break;

					default:
						$type = PDO::PARAM_STR;
						
				}
				if(substr($key, 0, 1) != ':') $key = ':'.$key;
				self::$ST_Handler->bindValue($key, $val, $type);
			}
			
		}
		
	}
	// F�hre das aktuelle Prepared Statement aus (F�r Anfragen ohne R�ckgabe von Datens�tzen)
	public static function execute() {
	
		try {
		
			return self::$ST_Handler->execute();
			
		}catch(PDOException $e) {
		
			exit();
			
		}
		
	}
	// F�hre das aktuelle Prepared Statement aus und gebe das gesamte result set zur�ck
	public static function fetchAssoc() {
	
		if(self::execute() === true){
		
			$buffer = self::$ST_Handler->fetchAll(PDO::FETCH_ASSOC);
			if(is_array($buffer) && count($buffer) > 0) return $buffer;
			
		}else{
		
			return false;
			
		}
	}
	public static function rowCount(){
		
		if(self::execute() === true){
		
			return self::$ST_Handler->rowCount();
			
		}else{
		
			return false;
			
		}
	
	}
	// Gebe die ID des zuletzt eingef�gten Datensatzes zur�ck
	public static function getNewID() {
	
		try {
		
			return self::$DB_Handler->lastInsertId();
			
		}
		catch(PDOException $e) {
		
			exit();
			
		}
		
	}
}
?>