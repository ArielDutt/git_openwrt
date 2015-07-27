
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
deal with the captured packages here !!!!!!!!!
*/
void getPackage(u_char * arg,const struct pcap_pkthdr * pkthdr, const u_char * packet){
	//int * id = (int *) arg;	
	//printf("packet id : %d \n", ++(*id) );
	//printf("packet length: %d \n",pkthdr -> len );
	//printf("Number of bytes:%d\n",pkthdr -> caplen );

/*
	int i;
	for(i = 0;i < pkthdr -> len ;++i){
		printf("  %02x", packet[i] );
		if((i + 1) % 16 == 0){
			printf("\n");
		}
	}
	printf("\n");
*/
	//the SSID information

	int ssid_length = packet[63];
	//printf("the ssid length:%d\n",ssid_length );
	unsigned char  ssid[256];
	if(ssid_length != 0 ){
		int p=0,k,h=64;
		for(k =0;k < ssid_length; k++){
			ssid[p] = packet[h];
			p++;
			h++;
		}	
		ssid[p]='\0';
		printf("ssid:%s\n",ssid );
	}
	else {
		printf("ssid:Broadcast\n");
	}
	
	// the RSSI information,should be a negative integer
	printf("RSSI: %d dBm \n", (char)packet[22] );

	//the BSSID information
	printf("MAC address:");
	int j = 42;
	for(;j < 47 ;j++){
		printf(" %02x:",packet[j] );
	}
	printf(" %02x\n",packet[47]);

	//the channel information
	int support_rate_length_position = 63 + ssid_length + 2;
	int support_rate_length = packet[support_rate_length_position];
	//printf("tag length:%d\n", support_rate_length );
	int channel_position = support_rate_length_position + support_rate_length + 3;
	//printf("channel_position:%d\n",channel_position );
	int channel = packet[channel_position];
	printf("channel:%d\n",channel );

	// the capture time information
	time_t t = time(NULL);
	printf("information collection time:");
	printf(ctime(&t));
	
	printf("\n\n");
}

 int main(int argc, char const *argv[])
{
	char errBuf[PCAP_ERRBUF_SIZE];
	pcap_t * device = pcap_open_live("wlan0" , 65535 , 1 , 0 , errBuf);
	if(!device){
		printf("error:pcap_open_live(): %s\n",errBuf );
		exit(1);
	}

	struct bpf_program filter;
	pcap_compile(device, &filter, "wlan[0] == 0x80", 1 , 0 );
	pcap_setfilter(device,&filter);

	int id = 0;
	pcap_loop(device , -1, getPackage, (u_char *)& id);

	pcap_close(device);

	return 0;
}