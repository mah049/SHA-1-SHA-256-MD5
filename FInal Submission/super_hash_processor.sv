module super_hash_processor(input logic clk, reset_n, start,
 input logic [1:0] opcode,
 input logic [31:0] message_addr, size, output_addr,
 output logic done, mem_clk, mem_we,
 output logic [15:0] mem_addr,
 output logic [31:0] mem_write_data,
 input logic [31:0] mem_read_data);
 
 //States and Logic
  enum logic [5:0] {IDLE= 6'b000000, HOLD_M = 6'b000001, 
  H1_state_M = 6'b000010, H2_state_M = 6'b000011, H3_state_M= 6'b000100,H4_state_M = 6'b000101,
  COMP_M = 6'b000110, H5_state_M = 6'b000111,UPDATE_M = 6'b001000, 
  SET_M = 6'b001001, SHA1_START = 6'b001010, SHA256_START = 6'b001011, MD5_START = 6'b001100,
  STEP1_S1= 6'b001101, H1_state_S1 = 6'b001110, 
  H2_state_S1 = 6'b001111, H3_state_S1= 6'b100000,H4_state_S1 = 6'b100100, 
  H5_state_S1 = 6'b101000, HOLD_S1 = 6'b010111, HOLD_S2 = 6'b011111,
  UPDATE_S1 = 6'b101100, SET_S1 = 6'b110000,
  STEP1_S2=6'b110100, STEP2_S2=6'b111000, STEP3_S2=6'b111100,
  STEP4_S2=6'b010000, STEP5_S2 =6'b010001, H1_state_S2 = 6'b010011,
  H2_state_S2 = 6'b010100, H3_state_S2= 6'b010101,H4_state_S2 = 6'b010110, 
  COMP_S2 = 6'b111001,
  H5_state_S2 = 6'b011000,UPDATE_S2 = 6'b011001, SET_S2 = 6'b011010, 
  H6_state_S2 = 6'b011011, H7_state_S2 = 6'b011110, H8_state_S2 = 6'b100110, COMP = 6'b111110} state;
 
 //Declaring Message Digest which are 5 32-bit words H0...H5
 logic [31:0] H0,H1,H2,H3,H4,H5,H6,H7,a,b,c,d,e,f,g,h,temp,holder;
 logic [15:0] num_blocks;
 logic [15:0] word;
 logic [15:0] zero_pad_length;
 logic [15:0] word_count, count, zero_padding_word_count;
 logic [1:0] padding_zero_flag = 2'b00;
 logic [63:0] message_inbits; 
 logic [31:0] w[0:15];
 logic [7:0] w_counter, t_value,t, w2;
 logic [127:0] please;
 
 //General functions
function logic [15:0] determine_num_blocks(input logic [31:0] size);
  if ((size << 3) % 512 <= 447)
    determine_num_blocks = ((size << 3)/512) + 1;
  else
    determine_num_blocks = ((size << 3)/512) + 2;
endfunction 

// right rotation
function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [7:0] r);
  begin
    rightrotate = (x >> r) | (x << (32-r));
  end
endfunction


//SHA-1 Functions and Constants
function logic [159:0] hash_op(input logic [31:0] a, b, c, d, e, w,
                                   input logic [7:0] t);
  logic [31:0] f, k, temp, tc; // internal signals

  if (t <= 19) begin
    f = (b & c) | ((~b) & d);
    k = 32'h5a827999;
  end else if (t <= 39) begin
    f = b ^ c ^ d;
    k = 32'h6ed9eba1;
  end else if (t <= 59) begin
    f = (b & c) | (b & d) | (c & d);
    k = 32'h8f1bbcdc;
  end else begin
    f = b ^ c ^ d;
    k = 32'hca62c1d6; 
  end
  temp = ((a << 5)|(a >> 27)) + f + e + k + w;
  tc = ((b << 30)|(b >> 2));
  hash_op = {temp, a, tc, c, d};
endfunction

 function logic [31:0] pre_w1(input logic [31:0] word [0:15], input logic [7:0] counter);
  logic [31:0] t1;
  t1 = w[w_counter-2] ^ w[w_counter-7] ^ w[w_counter-13] ^ w[w_counter-15];	
  pre_w1 = t1;
 endfunction

//MD5 Functions and Constants
//MD5 S constants

//MD5 K constants
parameter int md5_k[0:63] = '{
  32'hd76aa478, 32'he8c7b756, 32'h242070db, 32'hc1bdceee,
  32'hf57c0faf, 32'h4787c62a, 32'ha8304613, 32'hfd469501,
  32'h698098d8, 32'h8b44f7af, 32'hffff5bb1, 32'h895cd7be,
  32'h6b901122, 32'hfd987193, 32'ha679438e, 32'h49b40821,
  32'hf61e2562, 32'hc040b340, 32'h265e5a51, 32'he9b6c7aa,
  32'hd62f105d, 32'h02441453, 32'hd8a1e681, 32'he7d3fbc8,
  32'h21e1cde6, 32'hc33707d6, 32'hf4d50d87, 32'h455a14ed,
  32'ha9e3e905, 32'hfcefa3f8, 32'h676f02d9, 32'h8d2a4c8a,
  32'hfffa3942, 32'h8771f681, 32'h6d9d6122, 32'hfde5380c,
  32'ha4beea44, 32'h4bdecfa9, 32'hf6bb4b60, 32'hbebfbc70,
  32'h289b7ec6, 32'heaa127fa, 32'hd4ef3085, 32'h04881d05,
  32'hd9d4d039, 32'he6db99e5, 32'h1fa27cf8, 32'hc4ac5665,
  32'hf4292244, 32'h432aff97, 32'hab9423a7, 32'hfc93a039,
  32'h655b59c3, 32'h8f0ccc92, 32'hffeff47d, 32'h85845dd1,
  32'h6fa87e4f, 32'hfe2ce6e0, 32'ha3014314, 32'h4e0811a1,
  32'hf7537e82, 32'hbd3af235, 32'h2ad7d2bb, 32'heb86d391
};
 
//MD5 g
function logic[3:0] md5_g(input logic [7:0] t);
  begin
    if (t <= 15)
      md5_g = t;
    else if (t <= 31)
      md5_g = (5*t + 1) % 16;
    else if (t <= 47)
      md5_g = (3*t + 5) % 16;
    else
      md5_g = (7*t) % 16;
  end
endfunction

//MD5 f
function logic[31:0] md5_f(input logic [7:0] h);
  begin
    if (h <= 15)begin
      md5_f = (b & c) | ((~b) & d);end
    else if (h <= 31)begin
      md5_f = (d & b) | ((~d) & c);end
    else if (h <= 47)begin
      md5_f = b ^ c ^ d;end
    else begin
      md5_f = c ^ (b | (~d));end
  end
endfunction
// MD5 hash round

parameter byte S[0:15] = '{
 8'd7, 8'd12, 8'd17, 8'd22,
 8'd5, 8'd9, 8'd14, 8'd20,
 8'd4, 8'd11, 8'd16, 8'd23,
 8'd6, 8'd10, 8'd15, 8'd21
};
function logic [31:0] get_S(input logic [5:0] t);
 logic [3:0] i;
 i = {t[5:4], t[1:0]};
 get_S = S[i];
endfunction
function logic [127:0] md5_op(input logic[31:0] a, b, c, d, w,
 input logic[5:0] i);
 logic [31:0] t1, t2;
 t1 = a + md5_f(i) + md5_k[i] + w;
 t2 = b + ((t1 << get_S(i))|(t1 >> (32-get_S(i))));
 md5_op = {d,t2,b,c}; 
endfunction
//SHA-256 Functions and Constants
// SHA256 K constants

 function logic [31:0] pre_w2(input logic [31:0] word [0:15], input logic [7:0] counter);
  logic [31:0] t1; 
  t1 = rightrotate(w[w_counter-14],7) ^ rightrotate(w[w_counter-14],18) ^ (w[w_counter-14] >>3);
  pre_w2 = t1;
 endfunction
 
 function logic [31:0] pre_w3(input logic [31:0] word [0:15], input logic [7:0] counter);
  logic [31:0] t1; 

  t1 = rightrotate (w[w_counter-1],17) ^ rightrotate(w[w_counter-1],19) ^ (w[w_counter-1] >> 10);		
  pre_w3= t1;
 endfunction 
 
 
parameter int sha256_k[0:63] = '{
  32'h428a2f98, 32'h71374491, 32'hb5c0fbcf, 32'he9b5dba5, 32'h3956c25b, 32'h59f111f1, 32'h923f82a4, 32'hab1c5ed5,
  32'hd807aa98, 32'h12835b01, 32'h243185be, 32'h550c7dc3, 32'h72be5d74, 32'h80deb1fe, 32'h9bdc06a7, 32'hc19bf174,
  32'he49b69c1, 32'hefbe4786, 32'h0fc19dc6, 32'h240ca1cc, 32'h2de92c6f, 32'h4a7484aa, 32'h5cb0a9dc, 32'h76f988da,
  32'h983e5152, 32'ha831c66d, 32'hb00327c8, 32'hbf597fc7, 32'hc6e00bf3, 32'hd5a79147, 32'h06ca6351, 32'h14292967,
  32'h27b70a85, 32'h2e1b2138, 32'h4d2c6dfc, 32'h53380d13, 32'h650a7354, 32'h766a0abb, 32'h81c2c92e, 32'h92722c85,
  32'ha2bfe8a1, 32'ha81a664b, 32'hc24b8b70, 32'hc76c51a3, 32'hd192e819, 32'hd6990624, 32'hf40e3585, 32'h106aa070,
  32'h19a4c116, 32'h1e376c08, 32'h2748774c, 32'h34b0bcb5, 32'h391c0cb3, 32'h4ed8aa4a, 32'h5b9cca4f, 32'h682e6ff3,
  32'h748f82ee, 32'h78a5636f, 32'h84c87814, 32'h8cc70208, 32'h90befffa, 32'ha4506ceb, 32'hbef9a3f7, 32'hc67178f2
};

// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
  begin
    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    ch = (e & f) ^ ((~e) & g);
    t1 = h + S1 + ch + sha256_k[t] + w;
    S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;

    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
  end
endfunction

//General assignment statements
//zero pad length is the number of blocks times 512 to get bits minus the 64 big message length
//minus the size of the message plus the 1 extra bit
assign zero_pad_length = (determine_num_blocks(size) * 512) - ((size<<3)+1) - 64;
assign message_inbits = size*8;
assign mem_clk = clk;

//MAIN CODE!!!!
always_ff @(posedge clk, negedge reset_n) begin
    if (!reset_n) begin
	   state <= IDLE;
	 end else begin
	   case(state)
		  IDLE: begin
		    if(start) begin
			   case(opcode)
				  2'b00:begin
				    done <= 0;
                H0 <= 32'h67452301;
                H1 <= 32'hefcdab89;
                H2 <= 32'h98badcfe;
                H3 <= 32'h10325476;
				    state <= MD5_START;
				  end
				  2'b01:begin
				    done <= 0;
                H0 <= 32'h67452301;
                H1 <= 32'hefcdab89;
                H2 <= 32'h98badcfe;
                H3 <= 32'h10325476;
                H4 <= 32'hc3d2e1f0;
				    state <= SHA1_START;
				  end
				  default:begin
				    done <= 0;
                H0 = 32'h6a09e667;
                H1 = 32'hbb67ae85;
                H2 = 32'h3c6ef372;
                H3 = 32'ha54ff53a;
                H4 = 32'h510e527f;
                H5 = 32'h9b05688c;
                H6 = 32'h1f83d9ab;
                H7 = 32'h5be0cd19;
				    state <= SHA256_START;
				  end
				endcase
			 end
		    end
        MD5_START: begin
   		  	a <= H0;
		      b <= H1;
			   c <= H2;
			   d <= H3;   		
            count <= 0;
				t <= 0;
				w2 <= 0;
				zero_padding_word_count <= 0;
				padding_zero_flag <= 2'b00;
				word_count <= 0;
				w_counter <= 0;
				t_value <= 0;
            state <= COMP_M;		
		  end  
		UPDATE_M:begin
		  		H0 <= H0 + a;
				H1 <= H1 + b;
				H2 <= H2 + c;
				H3 <= H3 + d;
				state <= SET_M;
		end
		SET_M: begin
		     a <= H0;
			  b <= H1;
			  c <= H2;
			  d <= H3;
			  if(word_count <= (size>>2)+2)begin
			    t_value <= 0;
				 t <= 0;
				 w2 <= 0;
             w_counter <= 0;
			   state <= COMP_M;
		    end  else begin
			    state <= H1_state_M;
			 end
		end
		COMP_M:begin
		    if(0 <= t_value && t_value <= 15) begin

			   mem_we <= 0;
				mem_addr <= message_addr + count;
			   count <= count + 1;
			 end
			 if(2 <= t_value && t_value <= 17) begin

					if(word_count == ((size) >> 2)) begin
					case (size % 4)
					0: w[w_counter] <= 32'h80000000; 
					1: w[w_counter] <= (mem_read_data & 32'hFF000000)|32'h00800000;
					2: w[w_counter] <= (mem_read_data & 32'hFFFF0000)|32'h00008000;
					3: w[w_counter] <= (mem_read_data & 32'hFFFFFF00)|32'h00000080;
					endcase
					padding_zero_flag <= 2'b01;
					end 
					else begin
					w[w_counter] <= mem_read_data;	
					end 
					if(padding_zero_flag == 2'b01)begin
						 if(zero_padding_word_count <= (zero_pad_length/32))begin 
							  w[w_counter] <= 32'h00000000;				
							zero_padding_word_count <= zero_padding_word_count+1;
						 end 
						 else begin 
							w[w_counter] <= message_inbits;
							count <= 0;
						 end						
					end
					if(w_counter < 15 )begin
					 w_counter <= w_counter + 1;
					end
					word_count <= word_count + 1;
			 end
			 if(3 <= t_value && t_value <= 66) begin
			    if(t_value <= 18) begin 	
					{a,b,c,d} <= md5_op(a, b, c, d, w[w2], t);
					if ( w2 < 15 ) begin
					  w2 <= w2 + 1;
					end
					t <= t + 1;
				 end else begin
               {a,b,c,d} <= md5_op(a, b, c, d, w[md5_g(t)], t); 
					t <= t + 1;
			   end
				//zero padding
			 end
			 		 
			 //UPDATE AND CHECK TO SEE IF MORE
			 if(t == 64)begin
				H0 <= H0 + a;
				H1 <= H1 + b;
				H2 <= H2 + c;
				H3 <= H3 + d;
				state <= SET_M;
			 end
			 else begin
			   //ALWAYS DO THIS
			   t_value <= t_value + 1;
			   state <= COMP_M;
		    end
		end
     
		H1_state_M: begin
		  mem_write_data <= H0 ;
		  mem_we <= 1;
		  mem_addr <= output_addr + count;
        count <= count + 1;	
		  state <= H2_state_M; 
		end
		H2_state_M: begin
		  mem_write_data <= H1;
		  state <= H3_state_M;
		  mem_addr <= output_addr + count;
        count <= count + 1;		
		end
		H3_state_M: begin
		  mem_write_data <= H2;
		  state <= H4_state_M;
		  mem_addr <= output_addr + count;
        count <= count + 1;		
		end
		H4_state_M: begin
		  mem_write_data <= H3;
		  state <= HOLD_M;
		  mem_addr <= output_addr + count;
        count <= count + 1; 	
		end
		HOLD_M: begin
		  done <= 1;
		  state <= IDLE;
		end
		   //END OF MD5
		  
		  
		  
		  
		  
		  
		  
		 
//beginning of sha1		
		SHA1_START:begin
   		  	a <= H0;
		      b <= H1;
			   c <= H2;
			   d <= H3;
			   e <= H4;          
            count <= 0;
				t <= 0;
				w2 <= 0;
				zero_padding_word_count <= 0;
			   padding_zero_flag = 2'b00;
				word_count <= 0;
				w_counter <= 0;
				t_value <= 0;
            state <= COMP;
			end					
		UPDATE_S1:begin
		  		H0 <= H0 + a;
				H1 <= H1 + b;
				H2 <= H2 + c;
				H3 <= H3 + d;
				H4 <= H4 + e;
				state <= SET_S1;
		end
		SET_S1: begin
		     a <= H0;
			  b <= H1;
			  c <= H2;
			  d <= H3;
			  e <= H4;
			  if(word_count <= (size>>2)+2)begin
			    t_value <= 0;
				 t <= 0;
				 w2 <= 0;
             w_counter <= 0;
			   state <= COMP;
		    end else begin
			    state <= H1_state_S1;
			 end
		end
		
		//BEGINNING of computation

COMP:begin
		    if(0 <= t_value && t_value <= 15) begin
			   mem_we <= 0;
				mem_addr <= message_addr + count;
			   count <= count + 1;
			 end
			 if(2 <= t_value && t_value <= 17) begin
					if(word_count == ((size) >> 2)) begin
					case (size % 4)
					0: w[w_counter] <= 32'h80000000; 
					1: w[w_counter] <= (mem_read_data & 32'hFF000000)|32'h00800000;
					2: w[w_counter] <= (mem_read_data & 32'hFFFF0000)|32'h00008000;
					3: w[w_counter] <= (mem_read_data & 32'hFFFFFF00)|32'h00000080;
					endcase
					padding_zero_flag <= 2'b01;
					end 
					else begin
					w[w_counter] <= mem_read_data;	
					end 
					if(padding_zero_flag == 2'b01)begin
						 if(zero_padding_word_count <= (zero_pad_length/32))begin 
							  w[w_counter] <= 32'h00000000;				
							zero_padding_word_count <= zero_padding_word_count+1;
						 end 
						 else begin 
							w[w_counter] <= message_inbits;
							count <= 0;
						 end						
					end
					if(word_count > ((size) >> 2)) begin
					end
					if(w_counter < 15 )begin
					 w_counter <= w_counter + 1;
					end
					word_count <= word_count + 1;
			 end
			 if(3 <= t_value && t_value <= 82) begin 	
					{a,b,c,d,e} <= hash_op(a, b, c, d, e, w[w2], t);
					if ( w2 < 15 ) begin
					  w2 <= w2 + 1;
					end
					t <= t + 1; 
			   end
				//zero padding
			 if(18 <= t_value && t_value <= 81) begin
            
			    w[w_counter] <= (pre_w1(w,w2-1) << 1) | (pre_w1(w,w2-1) >> 31);
			    //shift by 1 because 16 registers are filled
			    for (int i = 0; i<15; i++) begin
				   w[i] <= w[i+1];
			    end		
 			 end
					 
			 
			 
			 //UPDATE AND CHECK TO SEE IF MORE
			 if(t == 80)begin
			   state <= UPDATE_S1;
			 end
			 else begin
			   //ALWAYS DO THIS
			   t_value <= t_value + 1;
			   state <= COMP;
		    end
		end		
		
		
		//end COMP
		H1_state_S1: begin
		  mem_write_data <= H0;
		  mem_we <= 1;
		  mem_addr <= output_addr + count;
        count <= count + 1;	
		  state <= H2_state_S1; 
		end
		H2_state_S1: begin
		  mem_write_data <= H1;
		  state <= H3_state_S1;
		  mem_addr <= output_addr + count;
        count <= count + 1;		
		end
		H3_state_S1: begin
		  mem_write_data <= H2;
		  state <= H4_state_S1;
		  mem_addr <= output_addr + count;
        count <= count + 1;		
		end
		H4_state_S1: begin
		  mem_write_data <= H3;
		  state <= H5_state_S1;
		  mem_addr <= output_addr + count;
        count <= count + 1; 	
		end
		H5_state_S1: begin
		  mem_write_data <= H4;
		  state <= HOLD_S1;
		  mem_addr <= output_addr + count;
        count <= count + 1;  
		end
		
		HOLD_S1:begin
		  done <= 1;
		  state <= IDLE;
		end
			
		//END OF SHA1
		
		
		
		
		
		
		//SHA256 START
		SHA256_START:begin
   		  	a <= H0;
		      b <= H1;
			   c <= H2;
			   d <= H3;
            e <= H4;
            f <= H5;
            g <= H6;
            h <= H7;				
            count <= 0;
				padding_zero_flag <= 2'b00;
				zero_padding_word_count <= 0;
				word_count <= 0;
				w_counter <= 0;
				w2 <= 0;
				t <= 0;
				t_value <= 0;
            state <= COMP_S2;	
		end
UPDATE_S2:begin
		  		H0 <= H0 + a;
				H1 <= H1 + b;
				H2 <= H2 + c;
				H3 <= H3 + d;
				H4 <= H4 + e;
				H5 <= H5 + f;
				H6 <= H6 + g;
				H7 <= H7 + h;
				state <= SET_S2;
		end
		SET_S2: begin
		     a <= H0;
			  b <= H1;
			  c <= H2;
			  d <= H3;
			  e <= H4;
			  f <= H5;
			  g <= H6;
			  h <= H7;
		     a <= H0;
			  b <= H1;
			  c <= H2;
			  d <= H3;
			  e <= H4;
			  f <= H5;
			  g <= H6;
			  h <= H7;
			  if(word_count <= (size>>2)+2)begin
			    t_value <= 0;
				 t <= 0;
				 w2 <= 0;
             w_counter <= 0;
			   state <= COMP_S2;
		    end else begin
			    state <= H1_state_S2;
			 end;
		end
COMP_S2:begin
		    if(0 <= t_value && t_value <= 15) begin

			   mem_we <= 0;
				mem_addr <= message_addr + count;
			   count <= count + 1;
			 end
			 if(2 <= t_value && t_value <= 17) begin

					if(word_count == ((size) >> 2)) begin
					case (size % 4)
					0: w[w_counter] <= 32'h80000000; 
					1: w[w_counter] <= (mem_read_data & 32'hFF000000)|32'h00800000;
					2: w[w_counter] <= (mem_read_data & 32'hFFFF0000)|32'h00008000;
					3: w[w_counter] <= (mem_read_data & 32'hFFFFFF00)|32'h00000080;
					endcase
					padding_zero_flag <= 2'b01;
					end 
					else begin
					w[w_counter] <= mem_read_data;	
					end 
					if(padding_zero_flag == 2'b01)begin
						 if(zero_padding_word_count <= (zero_pad_length/32))begin 
							  w[w_counter] <= 32'h00000000;				
							zero_padding_word_count <= zero_padding_word_count+1;
						 end 
						 else begin 
							w[w_counter] <= message_inbits;
							count <= 0;
						 end						
					end
					if(word_count > ((size) >> 2)) begin
					end
					if(w_counter < 15 )begin
					 w_counter <= w_counter + 1;
					end
					word_count <= word_count + 1;
			 end
			 if(3 <= t_value && t_value <= 66) begin 	
					{a,b,c,d,e,f,g,h} <= sha256_op(a, b, c, d, e, f, g, h, w[w2], t);
					if ( w2 < 15 ) begin
					  w2 <= w2 + 1;
					end
					t <= t + 1; 
			   end
			 if(18 <= t_value && t_value <= 65) begin
              w[w_counter] <= w[w_counter-15] + pre_w2(w,w_counter) + w[w_counter-6] + pre_w3(w,w_counter);
				  for (int i = 0; i<15; i++) begin
				    w[i] <= w[i+1];
				  end	
 			 end
			 //UPDATE AND CHECK TO SEE IF MORE
			 if(t == 64)begin
			   state <= UPDATE_S2;
			 end
			 else begin
			   //ALWAYS DO THIS
			   t_value <= t_value + 1;
			   state <= COMP_S2;
		    end
		end
		
		H1_state_S2: begin
		  mem_write_data <= H0;
		  mem_we <= 1;
		  mem_addr <= output_addr + count;
        count <= count + 1;	
		  state <= H2_state_S2; 
		end
		H2_state_S2: begin
		  mem_write_data <= H1;
		  state <= H3_state_S2;
		  mem_addr <= output_addr + count;
        count <= count + 1;		
		end
		H3_state_S2: begin
		  mem_write_data <= H2;
		  state <= H4_state_S2;
		  mem_addr <= output_addr + count;
        count <= count + 1;		
		end
		H4_state_S2: begin
		  mem_write_data <= H3;
		  state <= H5_state_S2;
		  mem_addr <= output_addr + count;
        count <= count + 1; 	
		end
		H5_state_S2: begin
		  mem_write_data <= H4;
		  state <= H6_state_S2;
		  mem_addr <= output_addr + count;
        count <= count + 1; 
		end
		H6_state_S2: begin
		  mem_write_data <= H5;
		  state <= H7_state_S2;
		  mem_addr <= output_addr + count;
        count <= count + 1; 
		end
		H7_state_S2: begin
		  mem_write_data <= H6;
		  state <= H8_state_S2;
		  mem_addr <= output_addr + count;
        count <= count + 1; 
		end
		H8_state_S2: begin
		  mem_write_data <= H7;
		  state <= HOLD_S2;
		  mem_addr <= output_addr + count;
        count <= count + 1; 
		end
	   HOLD_S2:begin
		  done <= 1;
		  state <= IDLE;
		end	
		//END OF SHA256
		endcase
	 end
end
endmodule