<?php
// functions are static
class DirectoryTaversalTool {
    public static function getVulnerabilities($urls) {
        if (is_array($urls)) {
            foreach ($urls as $key => $url) {
                DirectoryTaversalTool::getVulnerability($url);
            }
        } else {
            DirectoryTaversalTool::getVulnerability($urls);
        }

    }

    public static function getParams($query_string) {
        parse_str($query_string, $arr);
        return array_values($arr);
    }

    public static function openFile($filename) {
        return preg_split('/\r\n|\n|\r/', trim(file_get_contents($filename)));
    }
    
    public static function getVulnerability($url) {
        $data = file_get_contents($url);
        $host = parse_url($url)["host"];
        if ($data) {
            preg_match_all('#\bhttps?://[^,\s()<>]+(?:\([\w\d]+\)|([^,[:punct:]\s]|/))#', $data, $links);
            foreach ($links[0] as $key => $link) {
                $urlComponents = parse_url($link);
                if ($urlComponents["host"] == $host) {
                    $params = DirectoryTaversalTool::getParams($urlComponents["query"]);
                    foreach ($params as $i => $param) {
                        if (preg_match('/.+\.[A-Za-z]{0,5}/', $param)) {
                            print_r($url . " contains this link: " . $link . "which could be vulnerable to directory traversal");
                        }
                    }
                }
            }
        }
    }
}

// usage: php directory-traversal.php [url or txt list of urls]
$urls = is_file($argv[1]) ? DirectoryTaversalTool::openFile($argv[1]) : $argv[1];
DirectoryTaversalTool::getVulnerabilities($urls);




