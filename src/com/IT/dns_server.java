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

        /*String sentence;
        int length;
        ByteBuffer b;*/
        while(true) {

            socket.receive(receivePacket);

            analyzePacket(receivePacket.getData());

            //InetAddress ip = InetAddress.getByAddress(new byte[] {(byte) 95, (byte) 215, (byte) 62, (byte) 5});

           // sentence = new String(receive.getData(), 0, receive.getLength(), "UTF-8");
            //length = receive.getLength();

            if (receivePacket.getLength() < 1) {
                break;
            }

            socket.send(receivePacket);

        }

        //System.out.println(sentence.trim());
        //System.out.println("size: " + length);


        socket.close();
    }

    private static void analyzePacket(byte[] data){

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
        int RD = (header & 256);
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

        // Extract query name that occurs after 96 bites/12 bytes
        String qNameString = "";
        while(!(String.format("%02x", data[offset])).equals("00")){

            // Get length of current word
            int wordLength = data[offset];

            // If the given length is not the first length, add a '.'
            if(!qNameString.equals("")){
                qNameString += ".";
            }

            offset++;

            // Read word given its length in byte array
            for(int i = 0; i < wordLength; i++){
                qNameString += (char) data[offset];
                offset++;
            }

        }

        //Find IP address in dns Table
        String IP = dnsTable.get(qNameString);

        // Verify that IP is in the list of host files
        if(IP == null){
           return;
        }

        // Convert IP Address string to 4 byte IP Address: n1.n2.n3.n4

        int n1 = Integer.parseInt(IP.substring(0, IP.indexOf('.')));
        IP = IP.substring(IP.indexOf('.')+1);
        int n2 = Integer.parseInt(IP.substring(0, IP.indexOf('.')));
        IP = IP.substring(IP.indexOf('.')+1);
        int n3 = Integer.parseInt(IP.substring(0, IP.indexOf('.')));
        IP = IP.substring(IP.indexOf('.')+1);
        int n4 = Integer.parseInt(IP.substring(0));

        // Convert String IP to byte array
        Byte[] ip = {(byte) n1, (byte) n2, (byte) n3, (byte) n4};

        //Check query type and query class
        offset+=2;
        if(data[offset] != 1){
            // Problem with query type
            return;
        }
        offset+=2;
        if(data[offset] != 1){
            // Problem with query class
            return;
        }
        offset++;

        // Begin modifying message to append response

        // Add ttl here
        offset+=4;

        // Add rd length = 4 to response
        data[offset] = 4;
        offset++;

        // Add IP address to response
        for(int i = 0; i < 4; i++){
            data[offset] = ip[i];
            offset++;
        }

        System.out.println("Received: " + data.length + " bytes: ");
        for (int i=0; i < data.length; i++)
            System.out.print(String.format("%02x ", data[i]));
        System.out.println("");
        for (int i=0; i < data.length; i++)
            if ((data[i] <= ' ') || (data[i] > '~'))
                System.out.print(String.format("%02x ", data[i]));
            else
                System.out.print(String.format("%c  ", data[i]));
        System.out.println("");

        // look at the bytes as big endian shorts
        // the wrap() method uses an existing byte array for the buffer

        //short[] shorts = new short[data.length/2];
        //ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN).asShortBuffer().get(shorts);

        // dump our buffer as shorts
        //for (int i=0; i < data.length/2; i++)
            //System.out.println("short[" + i + "] = " + shorts[i]);

        // another way we can create shorts is by manually putting 2 bytes together
        // internet format is big endian - the first byte has the more significant value
        // this one produces an unsigned result

        //int short_value = ((data[0] & 0xff) << 8) + (data[1] & 0xff);
        //System.out.println("first 16 bits = " + short_value);


        // demo of extracting bit fields (e.g., for dns)
        // grab the second group of two bytes and treat it as a 16 bit set of bits
        // bits are indexed left to right


        int v = (data[2] & 0xff) << 8 | (data[3] & 0xff);
        for (int i=0; i < 16; i++) {
            System.out.println("bit[" + i + "] = " + (v>>(15-i) & 1));
            // System.out.println("bit[" + i + "] = " + (v & 1<<(15-i)));
        }

        // for example qr, query/response = bit 0
        //boolean qr = ((v >> 15-0) & 1) == 1;
        //System.out.println("qr = " + qr);
/*
        // for example rd, recursion desired = bit 7
        boolean rd = ((v >> 15-7) & 1) == 1;
        System.out.println("rd = " + rd);

        // example of setting a bit. Let's set qr to 1
        v |= (1<<(15-0));
        // write v back to the packet buffer
        data[2] = (byte) ((v >> 8) & 0xff);
        data[3] = (byte) (v & 0xff);
*/
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
