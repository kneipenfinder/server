<?php

	require_once('../core/config.php');
	require_once('../core/database.php');
	require_once('../core/server.php');

	$server = new server();
	$server->run();
 
?>
