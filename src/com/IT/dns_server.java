package com.IT;

public class dns_server {

    public static void main(String[] args) {
        System.out.println("Daivik Sheth");

        int portNumber = 12345;

        if(args.length == 1) {
            if (args[0].equals("-p")) {
                portNumber =Integer.parseInt(args[1]);
            } else if (args[0].equals("-f")) {
                
            } else{
                System.err.println("usage: java dns_server [-p port#] [-f hostfile]");
            }
        }
    }
}
