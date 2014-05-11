<?php

/**
 *
 * Automatically generates the Wordpress page PHP files for advisories
 *
 * @author Tom Needham
 * @copyright 2014 Tom Needham tom@owncloud.com
 *
 * Handles the dynamic nature of the scurity advisories section on ownCloud.org
 *
 * Part 1: It generates the .php files used to produce the 'advisory' pages for each advisory
 * Part 2: It recreates the lists and menus that list the advisories.
 *
 * Usage: php gen.php <ADVISORIES REPO DIR> <WWW REPO DIR>
 * (example) 'php gen.php /home/tom/security-advisories /home/tom/www'
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU AFFERO GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with this library.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

// PART 1 - Create the advisory files

// 1.1 - Read the json files
$advisoriesdir = $argv[1];
$wwwrepo = $argv[2];
$advisoryfiles = array();
$software = array('desktop', 'mobile', 'server');
$risklevel = array(
	1 => 'Low',
	2 => 'Medium',
	3 => 'High',
	);
$advisories = array();

foreach($software as $type) {
	$files = scandir($advisoriesdir.'/'.$type);
	foreach($files as $file) {
		if($file != '.' && $file != '..') {
			$advisoryfiles[$type][basename($file, '.json')] = $advisoriesdir . '/' . $type . '/' . $file;
		}
	}
}

foreach($software as $type) {
	if(!empty($advisoryfiles[$type])){
		foreach($advisoryfiles[$type] as $advisoryfile) {
			// Read the file
			$file = file_get_contents($advisoryfile);
			$data = json_decode($file);
			if(!is_null($data)) {
				$advisories[$type][basename($advisoryfile, '.json')] = $data;
			}
		}
	}
}

// 1.2 - Generate the PHP advisory files
foreach($software as $type){
	if(!empty($advisories[$type])) {
		foreach($advisories[$type] as $identifier => $advisory) {
			$output = $wwwrepo . '/advisories/' . $type . '/' . $identifier;
			$template = file_get_contents(__DIR__.'/advisory-template.php');
			// Insert the data
			$template = str_replace('~~TITLE~~', htmlentities($advisory->Title), $template);
			$template = str_replace('~~IDENTIFIER~~', htmlentities($identifier), $template);die(var_dump($advisory));
			$template = str_replace('~~DATE~~', htmlentities(date('jS F o', $advisory->Timestamp)), $template);
			$template = str_replace('~~LEVEL~~', htmlentities($risklevel[$advisory->Risk]), $template);
			$template = str_replace('~~DESCRIPTION~~', htmlentities($advisory->Description), $template);
			$affectedversions = '';
			foreach($advisory->Affected as $affected) {
				$operator = isset($affected->Operator) ? $affected->Operator.' ' : '';
				$affectedversions .= '<li>ownCloud Server '.$operator.'<strong>'.$affected->Version.'</strong> ('.$affected->CVE.')</li>';
			}
			$template = str_replace('~~AFFECTEDVERSIONS~~', htmlentities($affectedversions), $template);
			$template = str_replace('~~ACTION~~', htmlentities($advisory->ActionTaken), $template);
			$acknowledgments = '';
			foreach($advisory->Acknowledgment as $acknowledgment) {
				$acknowledgments .= '<li>'.$acknowledgment->Name.' - '.$acknowledgment->Company.' ('.$acknowledgment->Mail.') - '.$acknowledgment->Reason.'</li>';
			}
			$template = str_replace('~~ACKNOWLEDGMENTS~~', htmlentities($acknowledgments), $template);
			file_put_contents($wwwrepo . '/advisories/' . $identifier . '.php', $template);
		}
	}
}
// PART 2 - Generate the menus and lists

// 2.1 - Sort the advisories into versions
$verisons = array();
foreach($software as $type) {
	$versions[$type] = array();
}

foreach($software as $type){
	foreach($advisories[$type] as $identifier => $advisory) {
		foreach($advisory->Affected as $affected) {
			if(!array_key_exists($affected->Version, $versions[$type])) {
				$versions[$type][$affected->Version] = array();
			}
			$versions[$type][$affected->Version][$identifier] = $advisory;
		}
	}
}
$versions = sortVersionArray($versions);

// 2.2 - Generate the main advisories page lists
foreach($software as $type) {
	 $data = '';
	 foreach($versions[$type] as $version => $advisories) {
	 	$data .= '<p>Version ' . $version . "</p>\n";
	 	$advisories = sortAdvisoriesByDate($advisories);
	 	foreach($advisories as $identifier => $advisory) {
	 		$data .= '<a href="/security/advisory?id='.$identifier.'">'.$advisory->Title.'</a><br>'."\n";
	 	}
	 	$data .= '<br><br>'."\n";
	 }
	 file_put_contents($wwwrepo . '/advisories/' . $type . '-list-part.php', $data);
}

// 2.3 - Generate the lists at the side of the advisories
$data = '';
foreach($software as $type) {
	$data .= '<p>ownCloud '.ucwords($type).'</p>'."\n";
	$count = 0;
	foreach($versions[$type] as $version => $advisories) {
		foreach($advisories as $identifier => $advisory) {
			if($count != 5) {
				$data .= '<a href="/security/advisory?id='.$identifier.'">'.$advisory->Title.'</a></br>';
				$count++;
			} else {
				break;
			}
		}
	}
}
file_put_contents($wwwrepo . '/advisories/advisory-side.php', $data);


// FUNCTION DEFINITIONS
function sortAdvisoriesByDate($advisories) {
	usort($advisories, function($a, $b) {
		if($a->Timestamp < $b->Timestamp) {
			return -1;
		} elseif($a->Timestamp > $b->Timestamp){
			return 1;
		} else {
			return 0;
		}
	});
	return $advisories;
}

function sortVersionArray($array) {
	$final = array();
	foreach($array as $type => $versions) {
		if(!empty($versions)) {
			foreach($versions as $version => $advisories) {
				$versionStrings[] = $version;
			}

			usort($versionStrings, function($a, $b) {
				// Compare major versions
				return version_compare($a, $b);
			});
			$newVersions = array();
			foreach($versionStrings as $versionString) {
				$newVersions[] = $versions[$versionString];
			}
			$final[$type] = $newVersions;
		} else {
			$final[$type] = array();
		}
	}
	return $final;
}
?>