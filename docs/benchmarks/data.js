window.BENCHMARK_DATA = {
  "lastUpdate": 1795125050239,
  "repoUrl": "https://github.com/Brainwires/webrtc-rs-rtc",
  "entries": {
    "WebRTC-RS Criterion Benchmarks": [
      {
        "commit": {
          "author": {
            "email": "joshguyette@yahoo.com",
            "name": "Josh Guyette",
            "username": "nightness"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "355ead82505164ad266731b5d04039a6151ad7e0",
          "message": "Merge pull request #3 from Brainwires/fix/benchmarks-on-push\n\nci(bench): bencher output so the push-to-master store step finds results",
          "timestamp": "2026-11-13T06:13:22-06:00",
          "tree_id": "ebe665cb87b7ee7eb1fd33f2d93fd0b02b542343",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/355ead82505164ad266731b5d04039a6151ad7e0"
        },
        "date": 1794572995584,
        "tool": "cargo",
        "benches": [
          {
            "name": "Benchmark MarshalTo",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 47,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 141,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Marshal",
            "value": 39,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 181,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport MarshalTo",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Marshal",
            "value": 39,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 168,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication MarshalTo",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Marshal",
            "value": 25,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 43,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack MarshalTo",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Marshal",
            "value": 27,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 68,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 81,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 70,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 94,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 185,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 200,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 47,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 48,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 48,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_GetNotFound",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Get",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 67,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 47,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_GetFrom",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_AddTo",
            "value": 59,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 45,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 236,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 161,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 248,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 251,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 41,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageType_Value",
            "value": 0,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_WriteTo",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadFrom",
            "value": 44,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkIsMessage",
            "value": 0,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_NewTransactionID",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFull",
            "value": 198,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 75,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_WriteHeader",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_CloneTo",
            "value": 55,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_AddTo",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkDecode",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_GetFrom",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo_BadLength",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_GetFrom",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/AddTo",
            "value": 38,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/GetFrom",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXOR",
            "value": 24,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_AddTo",
            "value": 48,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_GetFrom",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 1937,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 5938,
            "range": "± 27",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1247,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1271,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 236,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 260,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 397,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 342,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1029,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 843,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkIsChannelData",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Encode",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Decode",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/AddTo",
            "value": 38,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddTo",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 35,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 36,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 252763,
            "range": "± 11979",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 282120,
            "range": "± 1168",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "joshguyette@yahoo.com",
            "name": "Josh Guyette",
            "username": "nightness"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "dddbef430ae47b8a9e4773fdaf2ee8fc3257c394",
          "message": "Release 0.21.1+brainwires.2: ICE-TCP both roles, per-address mDNS names, PLI/FIR delivery (#4)\n\nICE over TCP between rtc peers in both role assignments, bounded RFC 4571 decoding, per-address mDNS names with IPv6, mDNS routed to ICE whatever its first byte, inbound PLI/FIR delivered to the application by default. See CHANGELOG.md and FORK.md.",
          "timestamp": "2026-11-14T08:13:37-06:00",
          "tree_id": "13f7d544e29ea013558bb7e27bb4d392dc8928ca",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/dddbef430ae47b8a9e4773fdaf2ee8fc3257c394"
        },
        "date": 1794666616445,
        "tool": "cargo",
        "benches": [
          {
            "name": "Benchmark MarshalTo",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 46,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 143,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Marshal",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 181,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport MarshalTo",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Marshal",
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 167,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication MarshalTo",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Marshal",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack MarshalTo",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Marshal",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 68,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 81,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 69,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 123,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 206,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 195,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 47,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 50,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 48,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_GetNotFound",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Get",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 68,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 45,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_GetFrom",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_AddTo",
            "value": 60,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 44,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 238,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 161,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 248,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 252,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 41,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageType_Value",
            "value": 0,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_WriteTo",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadFrom",
            "value": 44,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkIsMessage",
            "value": 0,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_NewTransactionID",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFull",
            "value": 193,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 74,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_WriteHeader",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_CloneTo",
            "value": 54,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_AddTo",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkDecode",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_GetFrom",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo_BadLength",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_GetFrom",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/AddTo",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/GetFrom",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXOR",
            "value": 24,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_AddTo",
            "value": 46,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_GetFrom",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 1726,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 6023,
            "range": "± 145",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1244,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1261,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 236,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 259,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 395,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 352,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1026,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 851,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkIsChannelData",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Encode",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Decode",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/AddTo",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddTo",
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 251846,
            "range": "± 2004",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 281835,
            "range": "± 2053",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "joshguyette@yahoo.com",
            "name": "Josh Guyette",
            "username": "nightness"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "5015649a351f7227ad36c1c1b3ae5fcb8f7f56c5",
          "message": "Release 0.21.1+brainwires.3: JSEP negotiation, data channel lifecycle, RTCP past nested interceptors (#5)\n\nRelease 0.21.1+brainwires.3: JSEP negotiation, data channel lifecycle, RTCP past nested interceptors",
          "timestamp": "2026-11-19T12:36:02-06:00",
          "tree_id": "e2a65266fe23ca4ebd3c50fb2b65f2c5ffd92a0d",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/5015649a351f7227ad36c1c1b3ae5fcb8f7f56c5"
        },
        "date": 1795114393867,
        "tool": "cargo",
        "benches": [
          {
            "name": "Benchmark MarshalTo",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 41,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 163,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Marshal",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 174,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport MarshalTo",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Marshal",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 160,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication MarshalTo",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Marshal",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack MarshalTo",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Marshal",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 61,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 83,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 73,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 118,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 207,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 184,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 39,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 47,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 49,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_GetNotFound",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Get",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 66,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 46,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_GetFrom",
            "value": 25,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_AddTo",
            "value": 43,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 35,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 217,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 144,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 283,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 282,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 40,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageType_Value",
            "value": 0,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_WriteTo",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadFrom",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkIsMessage",
            "value": 0,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_NewTransactionID",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFull",
            "value": 182,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 77,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_WriteHeader",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_CloneTo",
            "value": 57,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_AddTo",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkDecode",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_GetFrom",
            "value": 25,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo_BadLength",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_GetFrom",
            "value": 25,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/AddTo",
            "value": 40,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/GetFrom",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXOR",
            "value": 24,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_AddTo",
            "value": 48,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_GetFrom",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 1833,
            "range": "± 49",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 5375,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1292,
            "range": "± 37",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1322,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 235,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 261,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 371,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 302,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1252,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 886,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkIsChannelData",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Encode",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Decode",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/AddTo",
            "value": 35,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddTo",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 35,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 225769,
            "range": "± 1229",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 297027,
            "range": "± 4811",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "joshguyette@yahoo.com",
            "name": "Josh Guyette",
            "username": "nightness"
          },
          "committer": {
            "email": "noreply@github.com",
            "name": "GitHub",
            "username": "web-flow"
          },
          "distinct": true,
          "id": "c16bfdef6f7e173a2fa05f1cbf1eef2999bd0c66",
          "message": "Merge pull request #8 from Brainwires/release/0.21.1-brainwires.4\n\nRelease 0.21.1+brainwires.4: ICE restarts keep the data path, msid per stream, inactive pauses",
          "timestamp": "2026-11-19T15:33:47-06:00",
          "tree_id": "39c3b0f33f17af1041219663a7f3588be88afaf8",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/c16bfdef6f7e173a2fa05f1cbf1eef2999bd0c66"
        },
        "date": 1795125049425,
        "tool": "cargo",
        "benches": [
          {
            "name": "Benchmark MarshalTo",
            "value": 25,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 49,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 140,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Marshal",
            "value": 35,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 182,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport MarshalTo",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Marshal",
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 167,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication MarshalTo",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Marshal",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack MarshalTo",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Marshal",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 68,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 32,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 80,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 69,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 94,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 184,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 194,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 47,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 49,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 49,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_GetNotFound",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Get",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 68,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 46,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_GetFrom",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_AddTo",
            "value": 59,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 45,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 240,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 166,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 253,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 252,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 41,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageType_Value",
            "value": 0,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_WriteTo",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadFrom",
            "value": 44,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkIsMessage",
            "value": 0,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_NewTransactionID",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFull",
            "value": 193,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 75,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_WriteHeader",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_CloneTo",
            "value": 54,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_AddTo",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkDecode",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_GetFrom",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo_BadLength",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_GetFrom",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/AddTo",
            "value": 38,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/GetFrom",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXOR",
            "value": 24,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_AddTo",
            "value": 47,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_GetFrom",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 2063,
            "range": "± 75",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 5972,
            "range": "± 93",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1246,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1260,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 232,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 259,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 401,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 354,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1047,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 854,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkIsChannelData",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Encode",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Decode",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/AddTo",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddTo",
            "value": 35,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 35,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 38,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 250998,
            "range": "± 2897",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 281434,
            "range": "± 6058",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}