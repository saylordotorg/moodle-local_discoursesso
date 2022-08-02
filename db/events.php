<?php
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * local_discoursesso
 *
 *
 * @package    local
 * @subpackage discoursesso
 * @copyright  2019 Saylor Academy
 * @author     John Azinheira
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
*/

defined('MOODLE_INTERNAL') || die();

$observers = array(
    // Listen for when a user profile is updated.
    array(
        'eventname' => '\core\event\cohort_deleted',
        'includefile' => '/local/discoursesso/locallib.php',
        'callback' => 'local_discoursesso_cohort_deleted_handler',
        'internal' => false
    ),
    // Listen for when a user is added to a cohort.
        array(
        'eventname' => '\core\event\cohort_member_added',
        'includefile' => '/local/discoursesso/locallib.php',
        'callback' => 'local_discoursesso_cohort_member_added_handler',
        'internal' => false
    ),
    // Listen for when a user is removed from a cohort.
        array(
        'eventname' => '\core\event\cohort_member_removed',
        'includefile' => '/local/discoursesso/locallib.php',
        'callback' => 'local_discoursesso_cohort_member_removed_handler',
        'internal' => false
    ),
);