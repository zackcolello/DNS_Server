package com.IT;

import java.util.*;
import java.io.*;

public class dns_server {

    private static HashMap<String, String> dnsTable;

    public static void main(String[] args) throws IOException{


        FileInputStream fs = null;

            if(args.length == 2 && args[0].equals("-f")){
                fs = new FileInputStream(args[1]);
            }else if (args.length == 4 && args[0].equals("-f")){
                fs = new FileInputStream(args[1]);
            } else if (args.length == 4 && args[2].equals("-f")) {
                fs = new FileInputStream(args[3]);
            }

        if(fs != null) {
            createDnsTable(fs);
        }
    }

    private static void createDnsTable(FileInputStream fs) throws IOException{

        dnsTable = new HashMap<>();
        BufferedReader br = new BufferedReader(new InputStreamReader(fs));

        String line;
        while((line = br.readLine()) != null){

            line = line.trim();

            // Ignore blank lines
            if(line.length() < 1){
                continue;
            }

            // Ignore comments
            if(line.charAt(0) == '#'){
                continue;
            }else if(line.indexOf('#') != -1){
                line = line.substring(0, line.indexOf('#'));
                line = line.trim();
            }

            // Divide word into IP and Domain Name
            int separator = line.indexOf(' ');
            if(line.indexOf('\t') != -1) {
                if (separator != -1 && line.indexOf('\t') < separator){
                    separator = line.indexOf('\t');
                }else if (separator == -1){
                    separator = line.indexOf('\t');
                }
            }

            // Add IP and Domain Name to hashmap
            String ip = line.substring(0, separator);
            ip = ip.trim();
            String domainName = line.substring(separator+1);
            domainName = domainName.trim();

            dnsTable.put(domainName, ip);

        }

    }
}
