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
date_default_timezone_set('Europe/London');
// PART 1 - Create the advisory files

// 1.1 - Read the json files
$advisoriesdir = $argv[1];
$wwwrepo = $argv[2];
$advisoryfiles = array();
$software = array('server', 'mobile', 'desktop');
$risklevel = array(
	1 => 'Low',
	2 => 'Medium',
	3 => 'High',
	);
$advisories = array(
	'server' => array(),
	'desktop' => array(),
	'mobile' => array(),
	);
$adFound = 0;
$adCount = 0;

foreach($software as $type) {
	$files = scandir($advisoriesdir.'/'.$type);
	foreach($files as $file) {
		if($file != '.' && $file != '..' && $file != '.DS_Store') {
			$advisoryfiles[$type][basename($file, '.json')] = $advisoriesdir . $type . '/' . $file;
			$adFound++;
		}
	}
}

//DEBUG
//print_r($advisoryfiles);

foreach($software as $type) {
	if(!empty($advisoryfiles[$type])){
		foreach($advisoryfiles[$type] as $advisoryfile) {
			// Read the file
			$file = file_get_contents($advisoryfile);
			$data = json_decode($file);
			if(!is_null($data)) {
				$advisories[$type][basename($advisoryfile, '.json')] = $data;
			} else {
				echo 'Error decoding data for: '.basename($advisoryfile, '.json')."\n";
			}
		}
	}
}

//print_r($advisories);

// 1.2 - Generate the PHP advisory files
foreach($software as $type){
	if(!empty($advisories[$type])) {
		foreach($advisories[$type] as $identifier => $advisory) {
			// Debug
			echo ' Starting generation for: '.$identifier."\n";
			// Check for missing data!
			$fields = array(
				'Title',
				'Timestamp',
				'Risk',
				'Description',
				'Affected'
				);
			$continue = true;
			foreach($fields as $field) {
				// Check is present
				if(!isset($advisory->{$field})) {
					echo 'Advisory: '.$identifier.' is missing the \''.$field.'\' field.'."\n";
					$continue = false;
				}
			}
			if($continue) {
				$output = $wwwrepo . '/advisories/' . $type . '/' . $identifier;
				$template = file_get_contents(__DIR__.'/advisory-template.php');
				// Insert the data
				$template = str_replace('~~TITLE~~', $advisory->Title, $template);
				$template = str_replace('~~IDENTIFIER~~', htmlentities(str_replace('oc-sa-', 'oC-SA-', $identifier)), $template);
				$template = str_replace('~~DATE~~', htmlentities(date('jS F o', $advisory->Timestamp)), $template);
				$template = str_replace('~~LEVEL~~', $risklevel[$advisory->Risk], $template);
				$template = str_replace('~~DESCRIPTION~~', $advisory->Description, $template);
				$affectedversions = '';
				foreach($advisory->Affected as $affected) {
					$operator = isset($affected->Operator) ? $affected->Operator.' ' : '';
					$affectedversions .= '<li>ownCloud Server '.$operator.'<strong>'.$affected->Version.'</strong> ('.$affected->CVE.')</li>';
				}
				$template = str_replace('~~AFFECTEDVERSIONS~~', $affectedversions, $template);
				$action = isset($advisory->ActionTaken) ? $advisory->ActionTaken : '';
				$template = str_replace('~~ACTION~~', $action, $template);
				$acknowledgments = '';
				if(isset($advisory->Acknowledgment)) {
					foreach($advisory->Acknowledgment as $acknowledgment) {
						$company = isset($acknowledgment->Company) ? $acknowledgment->Company : '';
						$mail = isset($acknowledgment->Mail) ? $acknowledgment->Mail : '';
						$reason = isset($acknowledgment->Reason) ? $acknowledgment->Reason : '';
						$acknowledgments .= '<li>'.$acknowledgment->Name.' - '.$company.' ('.$mail.') - '.$reason.'</li>';
					}
				}
				$template = str_replace('~~ACKNOWLEDGMENTS~~', $acknowledgments, $template);
				file_put_contents($wwwrepo . '/advisories/' . $identifier . '.php', $template);
				$adCount++;
			} else {
				// Some fields missing
				echo 'FAILED. Some fields missing for advisory: '.$identifier."\n";
			}
		}
	}
}
echo 'Completed creating html files for '.$adCount.' of '.$adFound.' advisories found.'."\n";
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
	 	foreach($advisories as $advisory) {
	 		$data .= '<a href="/security/advisory?id='.$advisory->identifier.'">'.$advisory->Title.'</a><br>'."\n";
	 	}
	 	$data .= '<br>'."\n";
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
			if($count < 5) {
				$count++;
				$data .= '<a href="/security/advisory?id='.$identifier.'">'.$advisory->Title.'</a></br>';
			} else {
				break;
			}
		}
	}
}
file_put_contents($wwwrepo . '/advisories/advisory-side.php', $data);


// FUNCTION DEFINITIONS
function sortAdvisoriesByDate($advisories) {
	foreach ($advisories as $id => $ad) {
		$ad->identifier = $id;
	}
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
				return version_compare($b, $a);
			});

			$newVersions = array();
			foreach($versionStrings as $versionString) {
				$newVersions[$versionString] = $versions[$versionString];
			}
			$final[$type] = $newVersions;
		} else {
			$final[$type] = array();
		}
	}
	return $final;
}
?>