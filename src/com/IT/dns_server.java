package com.IT;

import java.util.*;
import java.io.*;
import java.net.*;
import java.nio.*;

public class dns_server {

    private static HashMap<String, String> dnsTable;

    public static void main(String[] args) throws IOException{

        //Error handling
        if(args.length > 4 || args.length % 2 != 0){
            System.out.println("Invalid number of arguments.");
            System.exit(-1);
        }

        int portNumber = 12345;
        FileInputStream fs = new FileInputStream(System.getProperty("user.dir") +"/hosts.txt");

        if(args.length == 2 && args[0].equals("-f")){
            fs = new FileInputStream(args[1]);
        } else if(args.length == 2 && args[0].equals("-p")){
            portNumber = Integer.parseInt(args[1]);
        } else if (args.length == 4 && args[0].equals("-f") && args[2].equals("-p")){
            fs = new FileInputStream(args[1]);
            portNumber = Integer.parseInt(args[3]);
        } else if (args.length == 4 && args[2].equals("-f") && args[0].equals("-p")) {
            fs = new FileInputStream(args[3]);
            portNumber = Integer.parseInt(args[1]);
        } else if(args.length > 0){
            System.out.println("Invalid arguments.");
            System.exit(-1);
        }

        // Create DNS Table Hash Map
        createDnsTable(fs);

        // Set up port
        byte[] receiveData = new byte[1024];
        DatagramSocket socket = new DatagramSocket(portNumber);
        DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);

        while(true) {

            receivePacket.setData(new byte[1024]);
            socket.receive(receivePacket);

            receivePacket.setData(analyzePacket(receivePacket.getData()));

            if (receivePacket.getLength() < 1) {

                break;
            }

            socket.send(receivePacket);

        }

        socket.close();
    }

    private static byte[] analyzePacket(byte[] data){

        int offset = 0;

        // Get ID
        int id = (short) (((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF));
        offset += 2;

        // Get all flags from QR (inclusive) to RCode (inclusive)
        short header = (short) (((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF));
        offset += 2;

        //Get query
        int QR = (header & (2 << 6));
        int opcode = (header & 30720) >>> 11;
        int AA = (header & 1024);
        int TC = (header & 512);
        int RD = ((header & 256) == 0) ? 0 : 1;
        int RA = (header & 128);
        int rcode = (header & 15);

        // Get counts, move by 2 bytes each

        int QDCount = (short) (((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF));
        offset += 2;
        int ANCount = (short) (((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF));
        offset += 2;
        int NSCount = (short) (((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF));
        offset += 2;
        int ARCount = (short) (((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF));
        offset += 2;


        //Modify QR flag
        int header2 =(data[2] & 0xff) << 8 | (data[3] & 0xff);
        header2 |= (1<<(15-0));
        data[2] = (byte) ((header2 >> 8) & 0xff);
        data[3] = (byte) (header2 & 0xff);

        //Modify AA flag
        header2 =(data[2] & 0xff) << 8 | (data[3] & 0xff);
        header2 |= (1<<15-5);
        data[2] = (byte) ((header2 >> 8) & 0xff);
        data[3] = (byte) (header2 & 0xff);

        //Modify TC flag
        header2 =(data[2] & 0xff) << 8 | (data[3] & 0xff);
        header2 |= (0<<15-6);
        data[2] = (byte) ((header2 >> 8) & 0xff);
        data[3] = (byte) (header2 & 0xff);

        //Modify RA flag
        header2 =(data[2] & 0xff) << 8 | (data[3] & 0xff);
        header2 |= (0<<15-8);
        data[2] = (byte) ((header2 >> 8) & 0xff);
        data[3] = (byte) (header2 & 0xff);

        byte[] response = new byte[1024];
        int responseOffset = 0;

        // Extract query name that occurs after 96 bites/12 bytes
        String qNameString = "";
        while(!(String.format("%02x", data[offset])).equals("00")){

            // Get length of current word
            int wordLength = data[offset];
            response[responseOffset] = data[offset];

            // If the given length is not the first length, add a '.'
            if(!qNameString.equals("")){
                qNameString += ".";
                response[responseOffset] = data[offset];

            }
            responseOffset++;
            offset++;

            // Read word given its length in byte array
            for(int i = 0; i < wordLength; i++){
                qNameString += (char) data[offset];
                response[responseOffset] = data[offset];
                responseOffset++;
                offset++;
            }

        }

        //Find IP address in dns Table
        String IP = dnsTable.get(qNameString);

        // Modify RC flag: 0 for no error, 3 for name error (dm does not exist)

        // Verify that IP is in the list of host files
        if(IP == null){

            // If IP not found, modify RCODE with 3
            header2 |= (0<<15-12);
            data[2] = (byte) ((header2 >> 8) & 0xff);
            data[3] = (byte) (header2 & 0xff);

            header2 |= (0<<15-13);
            data[2] = (byte) ((header2 >> 8) & 0xff);
            data[3] = (byte) (header2 & 0xff);

            header2 |= (1<<15-14);
            data[2] = (byte) ((header2 >> 8) & 0xff);
            data[3] = (byte) (header2 & 0xff);

            header2 |= (1<<15-15);
            data[2] = (byte) ((header2 >> 8) & 0xff);
            data[3] = (byte) (header2 & 0xff);

            byte[] returnArr = Arrays.copyOf(data, offset);

            return returnArr;
        }
        else {

            // If IP not found, modify RCODE with 0

            header2 |= (0 << 15 - 12);
            data[2] = (byte) ((header2 >> 8) & 0xff);
            data[3] = (byte) (header2 & 0xff);

            header2 |= (0 << 15 - 13);
            data[2] = (byte) ((header2 >> 8) & 0xff);
            data[3] = (byte) (header2 & 0xff);

            header2 |= (0 << 15 - 14);
            data[2] = (byte) ((header2 >> 8) & 0xff);
            data[3] = (byte) (header2 & 0xff);

            header2 |= (0 << 15 - 15);
            data[2] = (byte) ((header2 >> 8) & 0xff);
            data[3] = (byte) (header2 & 0xff);

            // Convert IP Address string to 4 byte IP Address: n1.n2.n3.n4

            int n1 = Integer.parseInt(IP.substring(0, IP.indexOf('.')));
            IP = IP.substring(IP.indexOf('.') + 1);
            int n2 = Integer.parseInt(IP.substring(0, IP.indexOf('.')));
            IP = IP.substring(IP.indexOf('.') + 1);
            int n3 = Integer.parseInt(IP.substring(0, IP.indexOf('.')));
            IP = IP.substring(IP.indexOf('.') + 1);
            int n4 = Integer.parseInt(IP.substring(0));

            // Convert String IP to byte array
            Byte[] ip = {(byte) n1, (byte) n2, (byte) n3, (byte) n4};

            //Check query type and query class
            offset += 2;
            responseOffset+=2;

            response[responseOffset] = data[offset];
            if (data[offset] != 1) {
                // Problem with query type
                return null;
            }

            offset += 2;
            responseOffset+=2;
            response[responseOffset] = data[offset];

            if (data[offset] != 1) {
                // Problem with query class
                return null;
            }
            offset++;
            responseOffset++;

            int requestSize = offset+1;

            // Begin modifying message to append response
            // Add 1 to Answer Record Count

            int qRecCount = (data[4] & 0xff) << 8 | (data[5] & 0xff);
            qRecCount |= (0 << 15 - 15);
            data[4] = (byte) ((qRecCount >> 8) & 0xff);
            data[5] = (byte) (qRecCount & 0xff);

            int ansRecCount = (data[6] & 0xff) << 8 | (data[7] & 0xff);
            ansRecCount |= (1 << 15 - 15);
            data[6] = (byte) ((ansRecCount >> 8) & 0xff);
            data[7] = (byte) (ansRecCount & 0xff);

            // Add ttl here
            offset +=3;
            responseOffset+=3;
            data[offset] = (byte) 10;
            response[responseOffset] = (byte) 10;
            responseOffset++;
            offset ++;

            response[responseOffset]=(byte)0;
            responseOffset++;
            data[offset] = (byte) 4;
            response[responseOffset] = (byte) 4;
            responseOffset++;
            offset++;

            // Add IP address to response
            for (int i = 0; i < 4; i++) {
                response[responseOffset] = ip[i];
                responseOffset++;
                //data[offset] = ip[i];
                offset++;
            }

            // Copy byte arrays to create the final return array

            byte[] returnArr = new byte[requestSize + response.length+4];
            int returnIndex = 0;

            for(int i = 0; i < requestSize-1; i++){
                returnArr[returnIndex] = data[i];
                returnIndex++;
            }

            for(int i = 0; i < response.length-1; i++){
                returnArr[returnIndex] = response[i];
                returnIndex++;
            }

            // Remove zeros at end

            int zeroCount = 0;
            int index = returnArr.length-1;
            while(returnArr[index] == (byte) 0){
                zeroCount++;
                index--;
            }

            byte[] returnArr2 = Arrays.copyOf(returnArr, returnArr.length-zeroCount);

            return returnArr2;

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

            // Add IP and Domain Name to hash map
            String ip = line.substring(0, separator);
            ip = ip.trim();
            String domainName = line.substring(separator+1);
            domainName = domainName.trim();

            dnsTable.put(domainName, ip);

        }

    }
}
