<?php
/**
 * @package Virus_Finder
 * @version 1.0.12
 */
/*
Plugin Name: Virus Finder
Plugin URI: http://wordpress.org/plugins/virus-finder/
Description: PHP virus, malware finder plugin. Smart and full scan for malware detection.
Author: Robert Buzsik
Version: 1.0.12
Author URI: http://wphospital.hu/
*/

if ( ! defined( 'ABSPATH' ) ) exit;

if (is_admin())
{
	define("virus_finder_maxtime", ini_get("max_execution_time")-2);
	add_action('admin_menu', 'virus_finder_menu');
	add_action('admin_init', 'virus_finder_init');
}
 
function virus_finder_menu()
{
	add_menu_page( 'Virus Finder Page', 'Virus Finder', 'manage_options', 'virus-finder', 'virus_finder_start' );
}
 
function virus_finder_start()
{
	set_time_limit(3600);
	
	if (phpversion() <= "4.3.0")  
	{
		echo '<div class="notice notice-error"><p>The program needs at least PHP 4.3.0</p></div>';
	}
	elseif(!ini_get("allow_url_fopen"))
	{
		echo '<div class="notice notice-error"><p>allow_url_fopen is disabled. Please enable it first.</p></div>';
	}
	else
	{
		wp_register_style( 'css', plugin_dir_url( __FILE__ ).'style/style.css' );
		wp_enqueue_style('css');
		wp_enqueue_script('js', plugin_dir_url( __FILE__ ).'style/script.js', array('jquery'));
		
		
		echo '
		<script type="text/javascript">var filename = "'.(admin_url('admin.php?page=virus-finder')."&virus_finder_token=".wp_create_nonce("virus_finder_token_action")).'";</script>		
		<div id="keret">
				<div class="Login">
					<h1>Virus Finder for Websites by <a href="http://wphospital.hu" target="_blank">wphospital.hu</a></h1>
					<div id="hiba">&nbsp;</div>
					<div id="search">';
		
		
			echo '<p>Currently scanning: <span id="cs">&nbsp;</span></p>
				<p>Files scanned: <span id="fs">&nbsp;</span></p>
				<p>Time elapsed: <span id="te">&nbsp;</span></p>
				<p>Suspicious objects: <span id="so">&nbsp;</span></p>
				<p>Detected objects: <span id="do">&nbsp;</span></p>
				<p style="text-align:center;height:29px" id="nincshiba"><a href="#" id="start" class="gomb">Scan Now</a><a style="display:none" href="#" id="startfull" class="gomb">Full Scan</a><a href="#" id="result" style="display:none" class="gomb">Show Results</a><span style="display:none" id="cleanbox"><span id="cleaning"><img width="16" height="16" style="border:0" alt="" src="'.plugin_dir_url( __FILE__ ).'style/tolt.gif"/></span><span id="cleaningtext">Scan in progress</span></span></p>
					</div>
					<div id="destroy">&nbsp;</div>
					<p style="text-align:center;display:none" id="finish"><b>Need help for removing viruses? Contact us at <a href="mailto:wphospital@wphospital.hu">wphospital@wphospital.hu</a></b><br/><br/><a href="'.admin_url('admin.php?page=virus-finder').'" class="gomb">Finish</a></p>
			</div></div>';
	}
}

function virus_finder_init()
{
	$ok=0;
	if (isset($_POST["oldtorol"]) || isset($_POST["ellenoriz"]) || isset($_POST["result"]) || isset($_POST["start"]) || isset($_POST["checked"]) || isset($_GET["time"]))
	{
		if (!isset($_GET['virus_finder_token']) || (isset($_GET['virus_finder_token']) && !wp_verify_nonce($_GET['virus_finder_token'], 'virus_finder_token_action')))
		{
			//die("Token error");
			$ok=0;
		}
		else
		{
			$ok=1;
		}
	}
	
	if ($ok==1)
	{
		$upload_dir=wp_upload_dir();
		$dir=$upload_dir['basedir']."/";
		if (!is_dir( $dir.'wphospital.hu/' )) 
		{
			wp_mkdir_p( $dir.'wphospital.hu/' );
			
			$rand="virus_finder_".wp_rand();
			wp_mkdir_p( $dir.'wphospital.hu/'.$rand."/" );
		}
		
		$db=0;
		if (is_dir($dir.'wphospital.hu/')) 
		{
			if ($dh = opendir($dir.'wphospital.hu/')) 
			{
				while (($fajlname = readdir($dh)) !== false) 
				{
					if ($fajlname == "." || $fajlname == ".." || $fajlname == ".htaccess"|| $fajlname == "index.php") continue;
					$db++;
					if (is_dir($dir.'wphospital.hu/'.$fajlname)) $rand_dir=$fajlname;
				}
				closedir($dh);
			}
		}
		
		$rand=str_replace("virus_finder_","",$rand_dir);
		if (!(is_numeric($rand) && strlen($rand)>1) || $db!=1 || strlen($rand_dir)<15)
		{
			die("Wrong dir!");
		}

		if (isset($_POST["oldtorol"]))
		{
			if (is_dir($dir."wphospital.hu/")) virus_finder_rmdirr($dir."wphospital.hu/");
			
			die("OK");
		}
		elseif (isset($_POST["ellenoriz"]))
		{
			if (is_file($dir."wphospital.hu/".$rand_dir."/start.txt")) die("van");
			die("nincs");
		}
		elseif (isset($_POST["result"]))
		{
			$vanvirus=$vangyanus=0;
			$irni="";
			if (is_file($dir."wphospital.hu/".$rand_dir."/result_virus.txt"))
			{
				$vanvirus=1;
				$t=explode("\n",file_get_contents($dir."wphospital.hu/".$rand_dir."/result_virus.txt"));
				foreach ($t as $v)
				{
					if (strlen(trim($v))>1) $irni.="<tr><td class=\"virus\">Virus</td><td>".trim($v)."</td></tr>";
				}
			}
			
			if (is_file($dir."wphospital.hu/".$rand_dir."/result_suspicious.txt"))
			{
				$vangyanus=1;
				$t=explode("\n",file_get_contents($dir."wphospital.hu/".$rand_dir."/result_suspicious.txt"));
				foreach ($t as $v)
				{
					if (strlen(trim($v))>1) $irni.="<tr><td class=\"suspicious\">Suspicious</td><td>".trim($v)."</td></tr>";
				}
			}
			
			$szoveg="";
			if ($vanvirus==1) $szoveg="wphospital.hu/".$rand_dir."/virus/ folder";
			elseif ($vangyanus==1) $szoveg="wphospital.hu/".$rand_dir."/suspicious/ folder";
					
			if ($vanvirus==1 && $vangyanus==1) $szoveg="wphospital.hu/".$rand_dir."/virus/ and wphospital.hu/".$rand_dir."/suspicious/ folders";
			
			if ($irni=="") echo "<p style=\"text-align:center\"><b>No Threats Identified!</b></p>";
			else
			{
				echo '<p style="text-align:center"><b>The copy of the below files can be found in the uploads/'.$szoveg.'.</b><p>
				<table id="resulttable" width="100%" cellspacing="0" cellpadding="0" border="0">
					<tr><th>Category</th><th>Location</th></tr>
					'.$irni.'
				</table>';
			}		
			exit;
		}
		elseif (isset($_POST["checked"]))
		{
			if (is_file($dir."wphospital.hu/".$rand_dir."/vege.txt") && $_POST["checked"]!=="last") echo "VEGE";
			
			if (is_file($dir."wphospital.hu/".$rand_dir."/hiba.txt") && $_POST["checked"]!=="last")
			{
				$irni="HIBA&@&".file_get_contents($dir."wphospital.hu/".$rand_dir."/hiba.txt");
				echo $irni;
				exit;
			}
			
			$db=$virusos=$gyanus=0;
			
			if (is_file($dir."wphospital.hu/".$rand_dir."/result_suspicious.txt"))
			{
				$t=explode("\n",file_get_contents($dir."wphospital.hu/".$rand_dir."/result_suspicious.txt"));
				$gyanus=count($t)-1;
			}
			
			if (is_file($dir."wphospital.hu/".$rand_dir."/result_virus.txt"))
			{
				unset($t);
				$t=explode("\n",file_get_contents($dir."wphospital.hu/".$rand_dir."/result_virus.txt"));
				$virusos=count($t)-1;
			}
			
			$aktfajl="";
			if (is_file($dir."wphospital.hu/".$rand_dir."/result_checked.txt")) $db=filesize($dir."wphospital.hu/".$rand_dir."/result_checked.txt");
			if (is_file($dir."wphospital.hu/".$rand_dir."/result_current.txt")) $aktfajl=file_get_contents($dir."wphospital.hu/".$rand_dir."/result_current.txt");
			
			echo "&@&".$virusos."&@&".$gyanus."&@&".$db."&@&".$aktfajl; 		
			exit;
		}
		elseif (isset($_POST["start"]) || isset($_GET["time"]))
		{
			define("virus_finder_startTime", virus_finder_microtime_float());
			
			/*
			$fp = fopen($dir."wphospital.hu/.htaccess", "w");
			fwrite($fp, "deny from all");
			fclose($fp);
			*/
			
			insert_with_markers($dir."wphospital.hu/.htaccess","Virus Finder","deny from all");
			
			$fp = fopen($dir."wphospital.hu/".$rand_dir."/start.txt", "w");
			fwrite($fp, time());
			fclose($fp);
			
			if (is_file($dir."wphospital.hu/".$rand_dir."/hiba.txt")) unlink($dir."wphospital.hu/".$rand_dir."/hiba.txt");
			
			if (is_file($dir."wphospital.hu/".$rand_dir."/md5.txt")) $md5ttomb=explode("\n",gzuncompress(file_get_contents($dir."wphospital.hu/".$rand_dir."/md5.txt")));
			else
			{
				$md5list=file_get_contents("http://scan.wphospital.hu/malware_finder/md5_pack.txt");
				$fp = fopen($dir."wphospital.hu/".$rand_dir."/md5.txt", "w");
				fwrite($fp, $md5list);
				fclose($fp);
				
				$md5ttomb=explode("\n",gzuncompress($md5list));
			}
			
			foreach ($md5ttomb as $sor)
			{
				unset($t,$t2);
				$t=explode(" *",$sor);
				$t2 = explode("\\",$t[1]);
				$md5t[trim($t[0])]=trim($t2[count($t2)-1]);
			}
			
			
			if (!is_dir($dir."wphospital.hu/".$rand_dir."/suspicious/")) mkdir($dir."wphospital.hu/".$rand_dir."/suspicious/",0755);
			if (!is_dir($dir."wphospital.hu/".$rand_dir."/checked/")) mkdir($dir."wphospital.hu/".$rand_dir."/checked/",0755);
			if (!is_dir($dir."wphospital.hu/".$rand_dir."/virus/")) mkdir($dir."wphospital.hu/".$rand_dir."/virus/",0755);
			
			$string="<?php\n// Silence is golden.";
			
			if (!is_file($dir."wphospital.hu/index.php"))
			{
				$fp = fopen($dir."wphospital.hu/index.php", "w");
				fwrite($fp, $string);
				fclose($fp);
			}
			
			if (!is_file($dir."wphospital.hu/".$rand_dir."/index.php"))
			{
				$fp = fopen($dir."wphospital.hu/".$rand_dir."/index.php", "w");
				fwrite($fp, $string);
				fclose($fp);
			}
			
			if (!is_file($dir."wphospital.hu/".$rand_dir."/suspicious/index.php"))
			{
				$fp = fopen($dir."wphospital.hu/".$rand_dir."/suspicious/index.php", "w");
				fwrite($fp, $string);
				fclose($fp);
			}
			
			if (!is_file($dir."wphospital.hu/".$rand_dir."/checked/index.php"))
			{
				$fp = fopen($dir."wphospital.hu/".$rand_dir."/checked/index.php", "w");
				fwrite($fp, $string);
				fclose($fp);
			}
			
			if (!is_file($dir."wphospital.hu/".$rand_dir."/virus/index.php"))
			{
				$fp = fopen($dir."wphospital.hu/".$rand_dir."/virus/index.php", "w");
				fwrite($fp, $string);
				fclose($fp);
			}
			
			
			$fodir=dirname(dirname(dirname(dirname(__FILE__))))."/";
			
			$fajlok = virus_finder_mappaolvas($fodir);
			foreach($fajlok as $fajl)
			{
				virus_finder_mappakolvas($fodir.$fajl,$dir,$md5t,$rand_dir);
			}
			
			$fp = fopen($dir."wphospital.hu/".$rand_dir."/vege.txt", "w");
			fwrite($fp, time());
			fclose($fp);	
		}
	}
}


function virus_finder_mappakolvas($path,$dir,$md5t,$rand_dir)
{
	if (!is_readable($path)) return; 
	
	if (virus_finder_maxtime < (virus_finder_microtime_float()- virus_finder_startTime))
	{
		$fp = fopen($dir."wphospital.hu/".$rand_dir."/round.txt", "a");
		fwrite($fp, ".");
		fclose($fp);
		
		if (strlen(file_get_contents($dir."wphospital.hu/".$rand_dir."/round.txt"))>100)
		{
			$fp = fopen($dir."wphospital.hu/hiba.txt", "w");
			fwrite($fp, "Possible infinite loop, try to increase the max execution time! Contact your service provider!");
			fclose($fp);
		}

		header("Location: ".admin_url('admin.php?page=virus-finder')."&virus_finder_token=".$_GET["virus_finder_token"]."&time=".time());
		exit;
	}

	if(is_dir($path))
	{
		$path = rtrim($path, "/")."/";
		if (strpos($path, "/uploads/wphospital.hu/".$rand_dir."/")==false)
		{
			$cont = virus_finder_mappaolvas($path);
			for ($i = 0; $i < count($cont); $i++)
			{
				$fajl = $path.$cont[$i];
				
				if (is_file($fajl)) 
				{
					if (strpos($fajl, "/virus-finder/virus-finder.php")==false)
					{
						virus_finder_virusellenoriz($fajl,$dir,$md5t,$rand_dir);
					}
				}
				elseif (is_dir($fajl)) virus_finder_mappakolvas($fajl,$dir,$md5t,$rand_dir);
			}
		}
	} 
	elseif (is_file($path)) virus_finder_virusellenoriz($path,$dir,$md5t,$rand_dir);
}
	
function virus_finder_virusellenoriz($fajl,$dir,$md5t,$rand_dir)
{
	$extensions=array("php"); //now it checks only PHP files
	if (is_file($fajl))
	{
		$ftulaj = pathinfo($fajl);
		if (!in_array($ftulaj["extension"],$extensions)) return;
	}		

	$fmeret=filesize($fajl);
	if ($fmeret<1000000 && $fmeret>1)  //1mb-nál kisebb és 1 bájtnál nagyobb fájl ellenőrzése
	{
		$ujfajlnev=$dir."wphospital.hu/".$rand_dir."/checked/".str_replace("/","_",$fajl)."_".$md5tartalom.".txt";
		$tartalom=file_get_contents($fajl);
		$md5tartalom=md5($tartalom);

		if (isset($md5t[$md5tartalom]) && $md5t[$md5tartalom]==$ftulaj["basename"])
		{
			//MD5 OK, skipped"
		}
		elseif (is_file($ujfajlnev))
		{
			//already checked;
		}
		else
		{
			unset($firni);
			$eredmeny=virus_finder_post($tartalom,$fajl);
			
			if ($eredmeny=="OK")
			{
				$firni="OK";
				$tartalom="";
			}
			elseif ($eredmeny=="virus")
			{
				$mappa=$dir."wphospital.hu/".$rand_dir."/virus/".$ftulaj["dirname"]."/";
				$fnev=$ftulaj["basename"];
				if (!is_dir($mappa)) mkdir($mappa,0755,true);
				$firni="Virus";
				
				$fp = fopen($mappa.$fnev, "w");
				fwrite($fp, $tartalom);
				fclose($fp);
				
				$fp = fopen($dir."wphospital.hu/".$rand_dir."/result_virus.txt", "a");
				fwrite($fp, $ftulaj["dirname"]."/".$fnev."\n");
				fclose($fp);
			}
			elseif ($eredmeny=="suspicious")
			{
				$mappa=$dir."wphospital.hu/".$rand_dir."/suspicious/".$ftulaj["dirname"]."/";
				$fnev=$ftulaj["basename"];
				if (!is_dir($mappa)) mkdir($mappa,0755,true);
				$firni="Suspicious";
				
				$fp = fopen($mappa.$fnev, "w");
				fwrite($fp, $tartalom);
				fclose($fp);
				
				$fp = fopen($dir."wphospital.hu/".$rand_dir."/result_suspicious.txt", "a");
				fwrite($fp, $ftulaj["dirname"]."/".$fnev."\n");
				fclose($fp);
			}
			
			if (isset($firni))
			{
				$fp = fopen($ujfajlnev, "w");
				fwrite($fp, $firni);
				fclose($fp);
				
				$fp = fopen($dir."wphospital.hu/".$rand_dir."/result_checked.txt", "a");
				fwrite($fp, ".");
				fclose($fp);
				
				$fp = fopen($dir."wphospital.hu/".$rand_dir."/result_current.txt", "w");
				fwrite($fp, $fajl);
				fclose($fp);
			}
			elseif ($eredmeny!="")
			{
				$fp = fopen($dir."wphospital.hu/".$rand_dir."/hiba.txt", "w");
				fwrite($fp, $eredmeny);
				fclose($fp);
				die($eredmeny);
			}
		
		}
	}
}

function virus_finder_post($data,$fajlnev)
{
	$params = array("http" => array(
		"method" => "POST",
		"timeout" => "5",
		"content" => "content=".urlencode(gzcompress($data))."&domain=".$_SERVER["HTTP_HOST"]."&fajlnev=".$fajlnev."&verzio=0.1&key=wpplugin2016"
	));
	
	$try=0;
	unset($fp);
	while (!$fp && $try<50)
	{
		$ctx = stream_context_create($params);
		$fp = @fopen("http://virusscanner.wphospital.hu/malware_finder/ellenorzo.php", "rb", false, $ctx);
		$try++;
	}
	
	$response = @stream_get_contents($fp);
	if ($response === false) die("No answer from the server");
	return $response;
}

function virus_finder_mappaolvas($directory)
{
	if (!is_dir($directory) || (false === $fh = @opendir($directory))) return false;

	$fajlok = array();
	while (false !== ($fajlname = readdir($fh))) 
	{
		if ($fajlname == "." || $fajlname == "..") continue;
		$fajlok[] = $fajlname;
	}

	closedir($fh);
	sort($fajlok);		
	return $fajlok;
}

function virus_finder_microtime_float()
{
	list($usec, $sec) = explode(" ", microtime());
	return ((float)$usec + (float)$sec);
}

function virus_finder_rmdirr($dir) 
{
	$fajlok = virus_finder_mappaolvas($dir);
	foreach($fajlok as $file) 
	{
		if(is_dir($dir.$file)) virus_finder_rmdirr($dir.$file."/");
		elseif (is_file($dir.$file)) unlink($dir.$file);
	}
	rmdir($dir);
}

?>