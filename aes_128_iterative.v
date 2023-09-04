`include "aes_key_expand_128"
`include "mixcolumn"
`include "sbox"
`include "shiftrows"
`include "subbytes"








module aes_128_iterative(clk, plaintext, key, ciphertext);
  input clk;
  input [127:0] plaintext;
  input [127:0] key;
  output [127:0] ciphertext;

  wire [127:0] round_keys[0:10];
  wire [127:0] state[0:10];

  // Key Expansion (generate 11 round keys)
  key_expansion ke1 (
    .clk(clk),
    .key(key),
    .round_keys(round_keys)
  );

  // Initial round (AddRoundKey)
  assign state[0] = plaintext ^ round_keys[0];

  // 9 rounds of AES operations
  genvar i;
  generate
    for (i = 0; i < 9; i = i + 1) begin : aes_round
      // SubBytes
      subbytes sb(
        .clk(clk),
        .data(state[i]),
        .s_data_out(state[i + 1])
      );

      // ShiftRows
      shiftrows sr(
        .clk(clk),
        .data_in(state[i + 1]),
        .data_out(state[i + 1])
      );

      // MixColumns
      mixcolumn mc(
        .clk(clk),
        .data_in(state[i + 1]),
        .data_out(state[i + 1])
      );

      // AddRoundKey
      assign state[i + 1] = state[i + 1] ^ round_keys[i + 1];
    end
  endgenerate

  // Final round (SubBytes, ShiftRows, AddRoundKey)
  subbytes sb_final(
    .clk(clk),
    .data(state[9]),
    .s_data_out(state[10])
  );

  shiftrows sr_final(
    .clk(clk),
    .data_in(state[10]),
    .data_out(state[10])
  );

  // Output ciphertext
  assign ciphertext = state[10];
endmodule
