
/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs
 *  and could serve as the starting point for developing your first PIN tool
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <queue>
#include <map>
#include <stack>
 /* ================================================================== */
 // Global variables 
 /* ================================================================== */

using namespace std;
int insCount = 0;
int next_address = 0;
ostream *trace_out = &cerr;
ostream *trace_out_for_graph = &cerr;
ostream *alignment_out = &cerr;
map<int, int> call_map;
stack<int> call_stack;
stack<int> return_address_stack;
ADDRINT main_txt_saddr;
ADDRINT main_img;
INT32 Usage() {

	cerr << "This tool prints out the number of dynamically executed " << endl <<
		"instructions, basic blocks and threads in the application." << endl << endl;

	cerr << KNOB_BASE::StringKnobSummary() << endl;

	return -1;
}

//VOID dumpInstruction(ADDRINT address, INS ins) {
VOID dumpInstruction(ADDRINT address, UINT32 insSize, const string *dis) {
	// trace_out header "ta,dec_addr,binary_code,instruction,stack_depth,return_address,block_leader"
	// string *dis = new string(INS_Disassemble(ins));
	// int insSize = INS_Size(ins);
	// string mnemonic = INS_Mnemonic(ins);
	// cerr << dis << endl;

	//    ADDRINT saddr= address -`;
	//	write 'ta'
	*trace_out << dec << insCount << ",";
	*alignment_out << dec << insCount << ",";
	//	write 'decimal address'
	*trace_out << dec << address << ",";
	*alignment_out << dec << address << ",";
	//	write 'hex address'
	//*trace_out << hex << address << ";";
	*alignment_out << hex << address << ",";
	//	write 'binary code'
	for (int i = 0; i < (int)insSize; i++)
	{
		*trace_out << hex << "\\x" << setfill('0') << setw(2) << (((unsigned int) *(unsigned char*)(address + i)) & 0xFF);
		*alignment_out << hex << "\\x" << setfill('0') << setw(2) << (((unsigned int) *(unsigned char*)(address + i)) & 0xFF);
		// cerr << "\\x" << setfill('0') << setw(2) << (((unsigned int) *(unsigned char*)(address + i)) & 0xFF);
	}
	*trace_out << ",";
	*alignment_out << ",";
	//	write 'instruction'
	*trace_out << '"' << *dis << '"' << ",";
	// cerr << hex << endl << dis << endl;

	//	set alignment & write 'instruction'
	int is_return = call_map.count(address);
	int related_address = call_map.find(address)->second;
	if (is_return) {
		call_map.erase(call_map.find(address));
		while (1) {
			int call_stack_top = call_stack.top();
			call_stack.pop();
			return_address_stack.pop();
			if (call_stack_top == related_address) {
				break;
			}
		}
	}
	for (int i = 0; i < (int)call_stack.size(); i++) {
		*alignment_out << ",";
	}
	*alignment_out << '"' << *dis << '"';
	//  write 'stack depth'
	*trace_out << call_stack.size() << ",";

	//	write 'return address'
	if (return_address_stack.empty()) {
		*trace_out << 0 << ",";
	}
	else {
		*trace_out << dec << return_address_stack.top() << ",";
	}

	//  split instruction to mnemonic & operand
	char *instruction = const_cast<char*>(dis->c_str());
	char *token = strtok(instruction, " ");
	char *mnemonic = (char *)malloc(sizeof(char)*strlen(token) + 1);
	memcpy(mnemonic, token, strlen(token)+1);
	token = strtok(NULL, "");
	char *operand;
	if (token != NULL) {
		operand = (char *)malloc(sizeof(char)*strlen(token) + 1);
		memcpy(operand, token, strlen(token)+1);
	}
	
	//	arrange call map & stack 
	if (!strncmp(mnemonic, "call", 5)) {
		// *trace_out << ";";
		// *trace_out << dec << address + insSize << ";";
		// *trace_out << hex << address + insSize;
		call_map.insert(make_pair(address + insSize, insCount));
		call_stack.push(insCount);
		return_address_stack.push(address + insSize);
	}

	//	write 'caller address'
	if (is_return) {
		// *trace_out << ";";
		// *trace_out << dec << related_address << ";";
		// *trace_out << hex << related_address;
	}

	// write 'block_reader'
	if (!(next_address - address)) {
		*trace_out << FALSE;
	}
	else {
		*trace_out << TRUE;
	}

	*trace_out << endl;
	*alignment_out << endl;
	insCount++;
	next_address = address + insSize;
}


VOID ImageLoad(IMG img, VOID *v)
{
	if (!IMG_IsMainExecutable(img))
		return;

	main_img = IMG_LowAddress(img);

	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
	{
		if (SEC_Name(sec) == ".text") {
			main_txt_saddr = SEC_Address(sec);
		}

		for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
		{
			// Open the RTN.
			RTN_Open(rtn);

			//          rtn_addr = rtn_addr-main_img;
			//            *out<<rtn_name<<":"<<StringFromAddrint(rtn_addr)<<endl;
			for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins))
			{
				string dis = INS_Disassemble(ins);
				// string mnemonic = INS_Mnemonic(ins);
				// INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(dumpInstruction), IARG_INST_PTR, IARG_UINT32, INS_Size(ins), IARG_PTR, ins, IARG_END);
				INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(dumpInstruction), IARG_INST_PTR, IARG_UINT32, INS_Size(ins), IARG_PTR, new string(dis), IARG_END); 
				// INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(dumpInstruction), IARG_INST_PTR, IARG_PTR, ins, IARG_END);
			}
			// Close the RTN.
			RTN_Close(rtn);
		}
	}
}


VOID Fini(INT32 code, VOID *v)
{

}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments,
 *                              including pin -t <toolname> -- ...
 */

int main(int argc, char *argv[])
{
	// Initialize PIN library. Print help message if -h(elp) is specified
	// in the command line or the command line is invalid 
	if (PIN_Init(argc, argv))
	{
		return Usage();
	}

	char *input_file_name = argv[6];
	char *token = strtok(input_file_name, "\\");
	char *base_file_name;
	while (token != NULL) {
		base_file_name = token;
		token = strtok(NULL, "\\");
	}
	// cerr << base_file_name << endl;

	char base_file_name2[40];
	char *bfn2_ptr = base_file_name2;
	memcpy(&base_file_name2, base_file_name, 40);
	char *suffix_name = ".trace";
	char *alignment_name = "_alignment.csv";
	strcat(base_file_name, suffix_name);
	strcat(bfn2_ptr, alignment_name);
	string call_trace_name = base_file_name;
	string alignment_trace_name = bfn2_ptr;

	if (!call_trace_name.empty()) { 
		trace_out = new std::ofstream(call_trace_name.c_str()); 
		*trace_out << "ta,dec_addr,binary_code,instruction,stack_depth,return_address,block_leader" << endl;
	}
	if (!alignment_trace_name.empty()) { alignment_out = new std::ofstream(alignment_trace_name.c_str()); }

	PIN_InitSymbols();
	IMG_AddInstrumentFunction(ImageLoad, 0);
	PIN_AddFiniFunction(Fini, 0);

	cerr << "===============================================" << endl;
	cerr << "This application is instrumented by MyPinTool" << endl;
	cerr << "===============================================" << endl;

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
