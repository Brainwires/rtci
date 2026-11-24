window.BENCHMARK_DATA = {
  "lastUpdate": 1795538600433,
  "repoUrl": "https://github.com/Brainwires/rtci",
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
          "id": "9a8917ef6de4c62071c8f304987a228117f05e31",
          "message": "Merge pull request #9 from Brainwires/release/0.21.1-brainwires.5\n\nRelease 0.21.1+brainwires.5: hardening",
          "timestamp": "2026-11-20T00:26:28-06:00",
          "tree_id": "245293316200ce576d22a17a15c1200baa0ce0c7",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/9a8917ef6de4c62071c8f304987a228117f05e31"
        },
        "date": 1795156906200,
        "tool": "cargo",
        "benches": [
          {
            "name": "Benchmark MarshalTo",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 24,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 103,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Marshal",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 102,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport MarshalTo",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Marshal",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 98,
            "range": "± 0",
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
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack MarshalTo",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Marshal",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 38,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 54,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 49,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 126,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 112,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 24,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 24,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_GetNotFound",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Get",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_GetFrom",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_AddTo",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 129,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 83,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 166,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 165,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 21,
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
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadFrom",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 6,
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
            "value": 10,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFull",
            "value": 91,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 35,
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
            "value": 28,
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
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_GetFrom",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo_BadLength",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_GetFrom",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/AddTo",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/GetFrom",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXOR",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_AddTo",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_GetFrom",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 969,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 3544,
            "range": "± 80",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1098,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 897,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 159,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 177,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 427,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 244,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 671,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 558,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkIsChannelData",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Encode",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Decode",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/AddTo",
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddTo",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 115365,
            "range": "± 964",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 137880,
            "range": "± 1102",
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
          "id": "cdcd67173b2ac4702f8798a1ace5e981ccbe0954",
          "message": "Merge pull request #11 from Brainwires/release/0.21.1-brainwires.6\n\nRelease 0.21.1+brainwires.6: a lost INIT ACK no longer stops a data channel from opening",
          "timestamp": "2026-11-20T04:49:28-06:00",
          "tree_id": "030a5e76f6cce7471a2e87fe98f113f0abd31ce9",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/cdcd67173b2ac4702f8798a1ace5e981ccbe0954"
        },
        "date": 1795172785649,
        "tool": "cargo",
        "benches": [
          {
            "name": "Benchmark MarshalTo",
            "value": 24,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 42,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 157,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Marshal",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 168,
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
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 156,
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
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack MarshalTo",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Marshal",
            "value": 22,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 60,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 25,
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
            "value": 68,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 109,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 234,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 177,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 46,
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
            "value": 64,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 44,
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
            "value": 42,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 207,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 134,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 273,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 271,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 38,
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
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadFrom",
            "value": 36,
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
            "value": 175,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 72,
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
            "value": 49,
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
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 25,
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
            "value": 32,
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
            "value": 24,
            "range": "± 1",
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
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXOR",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_AddTo",
            "value": 45,
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
            "value": 1778,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 5152,
            "range": "± 41",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1554,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1260,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 228,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 256,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 620,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 310,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1176,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 826,
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
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/AddTo",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 16,
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
            "value": 29,
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
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 219502,
            "range": "± 4575",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 277904,
            "range": "± 658",
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
          "id": "f36d9b2c8127b4b417efad83f9420a1dc7ff338a",
          "message": "Merge pull request #10 from Brainwires/release/0.22.0-brainwires.1\n\nRelease 0.22.0+brainwires.1: conformance across SCTP, JSEP, ICE, DTLS, RTP and stats",
          "timestamp": "2026-11-20T07:56:30-06:00",
          "tree_id": "4ada33059ee9a6aee66902f7a38f14ff61e1f4c7",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/f36d9b2c8127b4b417efad83f9420a1dc7ff338a"
        },
        "date": 1795184028172,
        "tool": "cargo",
        "benches": [
          {
            "name": "Benchmark MarshalTo",
            "value": 25,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 44,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 151,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Marshal",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 162,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport MarshalTo",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Marshal",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 150,
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
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 28,
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
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 58,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 26,
            "range": "± 0",
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
            "value": 124,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 223,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 175,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 41,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 43,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 47,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_GetNotFound",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Get",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 59,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_GetFrom",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_AddTo",
            "value": 49,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 201,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 138,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 260,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 262,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 36,
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
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadFrom",
            "value": 39,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 10,
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
            "value": 169,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 63,
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
            "value": 45,
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
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_GetFrom",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo_BadLength",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_GetFrom",
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/AddTo",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/GetFrom",
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXOR",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_AddTo",
            "value": 39,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_GetFrom",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 1642,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 5229,
            "range": "± 39",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1547,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1276,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 229,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 280,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 651,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 362,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1144,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 841,
            "range": "± 14",
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
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Decode",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/AddTo",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddTo",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 25,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 292149,
            "range": "± 1779",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 312220,
            "range": "± 17329",
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
          "id": "f0ebf8f2c1e28da83def5b01172025108115013a",
          "message": "Release 0.22.0+brainwires.2: sender binding, codec stats, RTX for explicit encodings, rejected sections\n\nRelease 0.22.0+brainwires.2: codec-less send encodings, sendEncodings RTX, rejected remote sections",
          "timestamp": "2026-11-20T10:58:32-06:00",
          "tree_id": "5e5dadc9b43cf7bf69e08df0e6702850108d5fbc",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/f0ebf8f2c1e28da83def5b01172025108115013a"
        },
        "date": 1795194895862,
        "tool": "cargo",
        "benches": [
          {
            "name": "Benchmark MarshalTo",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 127,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 10,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Marshal",
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 134,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport MarshalTo",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Marshal",
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 128,
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
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack MarshalTo",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Marshal",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 42,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 67,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 52,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 66,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 182,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 136,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_GetNotFound",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Get",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 44,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_GetFrom",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_AddTo",
            "value": 46,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 27,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 143,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 97,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 235,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 229,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 26,
            "range": "± 2",
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
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadFrom",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 8,
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
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFull",
            "value": 122,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 47,
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
            "value": 34,
            "range": "± 2",
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
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_GetFrom",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo_BadLength",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_GetFrom",
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/AddTo",
            "value": 24,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/GetFrom",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXOR",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_AddTo",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_GetFrom",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 1350,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 3826,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1253,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1016,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 194,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 209,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 518,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 250,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 924,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 681,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkIsChannelData",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Encode",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Decode",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/AddTo",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddTo",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 181500,
            "range": "± 620",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 188382,
            "range": "± 1149",
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
          "id": "29e3e7ef726c144b172f6d2286dd7d59e54b593c",
          "message": "Release 0.22.0+brainwires.3: renegotiation rebinding, transceiver removal, rejected sections, XR round-trip time\n\nRelease 0.22.0+brainwires.3: codec re-binding, rejected sections stop and are removed, XR round trip time",
          "timestamp": "2026-11-20T13:45:23-06:00",
          "tree_id": "e28e0b4f2cc39c5f663eeb4a836172b844003f68",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/29e3e7ef726c144b172f6d2286dd7d59e54b593c"
        },
        "date": 1795204922762,
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
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 157,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Marshal",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 167,
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
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 157,
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
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 27,
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
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 60,
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
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 80,
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
            "value": 95,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 194,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 168,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 40,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 44,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 46,
            "range": "± 1",
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
            "value": 63,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 42,
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
            "value": 41,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 208,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 135,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 273,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 272,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 39,
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
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadFrom",
            "value": 36,
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
            "value": 175,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 71,
            "range": "± 1",
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
            "value": 50,
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
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 25,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_GetFrom",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 32,
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
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXOR",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_AddTo",
            "value": 45,
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
            "value": 1789,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 5284,
            "range": "± 61",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1551,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1263,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 228,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 253,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 623,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 314,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1161,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 828,
            "range": "± 8",
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
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Decode",
            "value": 25,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/AddTo",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 15,
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
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 218271,
            "range": "± 3604",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 278275,
            "range": "± 5151",
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
          "id": "236bf18544f9649e0077104ede5b8b8010a95690",
          "message": "Release 0.22.0+brainwires.4: ECN / L4S statistics and RFC 8888 feedback\n\nRelease 0.22.0+brainwires.4: ECN / L4S marking and ECN / RFC 8888 statistics",
          "timestamp": "2026-11-20T17:54:53-06:00",
          "tree_id": "e6d5b5049a6ff973619142eddaaf0989af8f1951",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/236bf18544f9649e0077104ede5b8b8010a95690"
        },
        "date": 1795219847501,
        "tool": "cargo",
        "benches": [
          {
            "name": "Benchmark MarshalTo",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 124,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 10,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Marshal",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 132,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport MarshalTo",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Marshal",
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 127,
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
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack MarshalTo",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Marshal",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 42,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 65,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 49,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 80,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 180,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 135,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_GetNotFound",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Get",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 43,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_GetFrom",
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_AddTo",
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 146,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 96,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 238,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 233,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 28,
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
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadFrom",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 8,
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
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFull",
            "value": 122,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 48,
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
            "value": 34,
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
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_GetFrom",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo_BadLength",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_GetFrom",
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/AddTo",
            "value": 24,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/GetFrom",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXOR",
            "value": 17,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_AddTo",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_GetFrom",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 1245,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 3894,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1256,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1019,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 195,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 213,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 517,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 249,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 914,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 684,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkIsChannelData",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Encode",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Decode",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/AddTo",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddTo",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 172161,
            "range": "± 206",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 187219,
            "range": "± 716",
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
          "id": "8916bc3048c2b2a53788639f57e4a64a4a4b4696",
          "message": "Release 0.22.0+brainwires.5: the controlled ICE agent follows a later nomination\n\nRelease 0.22.0+brainwires.5: the controlled ICE agent follows a later nomination (Chrome pair switch)",
          "timestamp": "2026-11-20T19:47:50-06:00",
          "tree_id": "8d50dab0c223d6d6a93589c77cc20484b290c536",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/8916bc3048c2b2a53788639f57e4a64a4a4b4696"
        },
        "date": 1795226664095,
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
            "value": 46,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 159,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 18,
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
            "value": 193,
            "range": "± 1",
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
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 181,
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
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 35,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack MarshalTo",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Marshal",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 74,
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
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 91,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 72,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 98,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 249,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 202,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 49,
            "range": "± 1",
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
            "value": 50,
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
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 74,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 48,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_GetFrom",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_AddTo",
            "value": 61,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 42,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 239,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 159,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 283,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 280,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 43,
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
            "value": 13,
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
            "value": 189,
            "range": "± 1",
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
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkDecode",
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_GetFrom",
            "value": 24,
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
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_GetFrom",
            "value": 24,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/AddTo",
            "value": 39,
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
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_AddTo",
            "value": 47,
            "range": "± 1",
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
            "value": 1835,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 6021,
            "range": "± 101",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1666,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1393,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 249,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 288,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 697,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 405,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1154,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 980,
            "range": "± 19",
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
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Decode",
            "value": 28,
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
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddTo",
            "value": 37,
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
            "value": 38,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 227403,
            "range": "± 23258",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 282878,
            "range": "± 1189",
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
          "id": "2da888bab24b739a6c29e95582e944ea3b7822b4",
          "message": "Merge pull request #17 from Brainwires/docs/conformance-audit\n\ndocs(conformance): clause-level audit of the WebRTC spec set",
          "timestamp": "2026-11-22T07:35:43-06:00",
          "tree_id": "4d25527b976908e1f013e139dc9805eaed86a502",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/2da888bab24b739a6c29e95582e944ea3b7822b4"
        },
        "date": 1795356207965,
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
            "value": 45,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 160,
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
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 171,
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
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 159,
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
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 28,
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
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 60,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 26,
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
            "value": 73,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 114,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 235,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 172,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 40,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 45,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 47,
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
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 64,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 42,
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
            "value": 42,
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
            "value": 211,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 138,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 281,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 279,
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
            "value": 178,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 72,
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
            "value": 51,
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
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 26,
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
            "value": 33,
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
            "value": 24,
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
            "value": 19,
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
            "value": 45,
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
            "value": 1801,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 5365,
            "range": "± 59",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1604,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1321,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 231,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 263,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 639,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 333,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1190,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 849,
            "range": "± 6",
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
            "value": 25,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/AddTo",
            "value": 36,
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
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 270137,
            "range": "± 2107",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 337307,
            "range": "± 15951",
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
          "id": "7b24165829204779fb90cec002f0c377bee8a589",
          "message": "Merge pull request #38 from Brainwires/conf/train\n\nConformance train: clause-level fixes across the WebRTC spec set",
          "timestamp": "2026-11-22T16:23:32-06:00",
          "tree_id": "dc25358cb0e811076adacf8ea0568a18e5d5278c",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/7b24165829204779fb90cec002f0c377bee8a589"
        },
        "date": 1795387201057,
        "tool": "cargo",
        "benches": [
          {
            "name": "Benchmark MarshalTo",
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 37,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 131,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Marshal",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 88,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport MarshalTo",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Marshal",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 88,
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
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 62,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack MarshalTo",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Marshal",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 80,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 11,
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
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 52,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 87,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 155,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 165,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 38,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 41,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 42,
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
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 64,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 48,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_GetFrom",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_AddTo",
            "value": 47,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 193,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 133,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 217,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 212,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 34,
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
            "value": 24,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 9,
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
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFull",
            "value": 153,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 65,
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
            "value": 45,
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
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_GetFrom",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo_BadLength",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_GetFrom",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/AddTo",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXOR",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_AddTo",
            "value": 40,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_GetFrom",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 1684,
            "range": "± 57",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 3592,
            "range": "± 138",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1336,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1118,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 219,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 244,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 567,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 335,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1207,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 1043,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkIsChannelData",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Encode",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Decode",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/AddTo",
            "value": 29,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddTo",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 220523,
            "range": "± 4831",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 219237,
            "range": "± 1888",
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
          "id": "bdb62cbefe294b63d39af5f9466d49fdd3779323",
          "message": "Merge pull request #39 from Brainwires/conf/train-2\n\nConformance train 2",
          "timestamp": "2026-11-22T16:49:17-06:00",
          "tree_id": "d136f4fb2e5a549aba302a9ab85968a149dd1e60",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/bdb62cbefe294b63d39af5f9466d49fdd3779323"
        },
        "date": 1795388785079,
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
            "value": 48,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 149,
            "range": "± 4",
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
            "value": 34,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 107,
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
            "value": 33,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 108,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication MarshalTo",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Marshal",
            "value": 27,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 73,
            "range": "± 1",
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
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 87,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 34,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 99,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 66,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 103,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 179,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 207,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 46,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 50,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 52,
            "range": "± 1",
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
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 75,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 58,
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
            "value": 42,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 249,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 178,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 259,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 250,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 42,
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
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 12,
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
            "value": 206,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 79,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_WriteHeader",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_CloneTo",
            "value": 58,
            "range": "± 2",
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
            "value": 35,
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
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 39,
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
            "value": 37,
            "range": "± 1",
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
            "value": 1935,
            "range": "± 44",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 4660,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1583,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1289,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 263,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 286,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 718,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 420,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1356,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 1159,
            "range": "± 16",
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
            "value": 5,
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
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddTo",
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 38,
            "range": "± 2",
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
            "value": 252373,
            "range": "± 3997",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 282013,
            "range": "± 888",
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
          "id": "732d02bdf9a133e49c3e26ef836b43ce76178571",
          "message": "Merge pull request #40 from Brainwires/conf/train-3\n\nConformance train 3",
          "timestamp": "2026-11-22T17:29:15-06:00",
          "tree_id": "8892635d28b8950b74995026f06e36c92b3388af",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/732d02bdf9a133e49c3e26ef836b43ce76178571"
        },
        "date": 1795391172731,
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
            "value": 48,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 148,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 15,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Marshal",
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 107,
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
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 107,
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
            "value": 25,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 72,
            "range": "± 1",
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
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 88,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 34,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 97,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 66,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 119,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 216,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 212,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 47,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 49,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 52,
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
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 80,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 58,
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
            "value": 91,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 43,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 247,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 175,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 260,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 257,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 45,
            "range": "± 1",
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
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 12,
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
            "value": 220,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 79,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_WriteHeader",
            "value": 4,
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
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkDecode",
            "value": 34,
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
            "value": 39,
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
            "value": 49,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_GetFrom",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 1973,
            "range": "± 152",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 4624,
            "range": "± 101",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1583,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1289,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 263,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 286,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 725,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 413,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1421,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 1251,
            "range": "± 36",
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
            "value": 5,
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
            "value": 17,
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
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 251987,
            "range": "± 2982",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 281251,
            "range": "± 531",
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
          "id": "278aa57111176381fb68ba6fcc9615288deafd4a",
          "message": "Merge pull request #41 from Brainwires/conf/train-4\n\nConformance train 4",
          "timestamp": "2026-11-22T18:28:40-06:00",
          "tree_id": "951422a0788c9a2bc01d80c64f416e50bc9f5921",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/278aa57111176381fb68ba6fcc9615288deafd4a"
        },
        "date": 1795394726148,
        "tool": "cargo",
        "benches": [
          {
            "name": "Benchmark MarshalTo",
            "value": 24,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 40,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 168,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Marshal",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 111,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport MarshalTo",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Marshal",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 110,
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
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 77,
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
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 88,
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
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 112,
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
            "value": 93,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 240,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 210,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 40,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 46,
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
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Get",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 75,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 59,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_GetFrom",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_AddTo",
            "value": 41,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 219,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 148,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 283,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 273,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 38,
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
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadFrom",
            "value": 33,
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
            "value": 184,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 76,
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
            "value": 54,
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
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 25,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_GetFrom",
            "value": 26,
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
            "value": 26,
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
            "value": 19,
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
            "value": 45,
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
            "value": 1715,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 4276,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1584,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1297,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 262,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 271,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 644,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 332,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1495,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 1115,
            "range": "± 15",
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
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddTo",
            "value": 31,
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
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 264598,
            "range": "± 6997",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 343442,
            "range": "± 13864",
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
          "id": "8a8c763a3ba0b2d6d69a7007a9ef47dd9e6cad55",
          "message": "Merge pull request #42 from Brainwires/conf/train-5\n\nConformance train 5",
          "timestamp": "2026-11-22T19:33:52-06:00",
          "tree_id": "b6068da9ceda01fb6b06121d88fe5e24ffbf44c8",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/8a8c763a3ba0b2d6d69a7007a9ef47dd9e6cad55"
        },
        "date": 1795398646824,
        "tool": "cargo",
        "benches": [
          {
            "name": "Benchmark MarshalTo",
            "value": 24,
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
            "value": 166,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Marshal",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 113,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport MarshalTo",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Marshal",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 110,
            "range": "± 3",
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
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 78,
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
            "value": 88,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 113,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 72,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 93,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 239,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 212,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 40,
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
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Get",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 76,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 60,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_GetFrom",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_AddTo",
            "value": 42,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 30,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 222,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 149,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 287,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 279,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 39,
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
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadFrom",
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 12,
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
            "value": 184,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 78,
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
            "value": 52,
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
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 25,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_GetFrom",
            "value": 26,
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
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/AddTo",
            "value": 36,
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
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_AddTo",
            "value": 45,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_GetFrom",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 1715,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 4223,
            "range": "± 105",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1591,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1302,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 261,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 274,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 641,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 324,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1448,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 1109,
            "range": "± 20",
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
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddTo",
            "value": 31,
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
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 263852,
            "range": "± 2470",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 338593,
            "range": "± 10679",
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
          "id": "9efb71d7c122667d7c4cf12da7128c5994fd8939",
          "message": "Merge pull request #43 from Brainwires/conf/train-6\n\nConformance train 6",
          "timestamp": "2026-11-22T20:28:06-06:00",
          "tree_id": "d1a576246770fbe7983aa69cc15343cc1377bb5a",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/9efb71d7c122667d7c4cf12da7128c5994fd8939"
        },
        "date": 1795401870112,
        "tool": "cargo",
        "benches": [
          {
            "name": "Benchmark MarshalTo",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 130,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Marshal",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 87,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport MarshalTo",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Marshal",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 87,
            "range": "± 3",
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
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 62,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack MarshalTo",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Marshal",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 80,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 11,
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
            "value": 80,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 52,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 72,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 145,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 168,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 40,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 40,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 42,
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
            "value": 12,
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
            "value": 49,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_GetFrom",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_AddTo",
            "value": 46,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 195,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 132,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 217,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 212,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 35,
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
            "value": 25,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 10,
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
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFull",
            "value": 155,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 66,
            "range": "± 2",
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
            "value": 46,
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
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_GetFrom",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo_BadLength",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_GetFrom",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/AddTo",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXOR",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_AddTo",
            "value": 40,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_GetFrom",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 1472,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 3487,
            "range": "± 242",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1335,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1114,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 218,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 245,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 562,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 330,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1186,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 1037,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkIsChannelData",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Encode",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Decode",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/AddTo",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddTo",
            "value": 29,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 219693,
            "range": "± 2276",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 219162,
            "range": "± 637",
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
          "id": "1794513a30d1f082c13d8ad167d83539ea9e243f",
          "message": "Merge pull request #44 from Brainwires/conf/train-7\n\nConformance train 7",
          "timestamp": "2026-11-22T21:46:11-06:00",
          "tree_id": "88ac5b2e74e525a61b6f037bde93d3176897197b",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/1794513a30d1f082c13d8ad167d83539ea9e243f"
        },
        "date": 1795406561380,
        "tool": "cargo",
        "benches": [
          {
            "name": "Benchmark MarshalTo",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 141,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 10,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Marshal",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 96,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport MarshalTo",
            "value": 9,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Marshal",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 94,
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
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 66,
            "range": "± 1",
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
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 75,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 25,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 97,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 57,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 73,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 204,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 179,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 40,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 42,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_GetNotFound",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Get",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 65,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 50,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_GetFrom",
            "value": 24,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_AddTo",
            "value": 37,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 193,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 132,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 264,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 252,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 34,
            "range": "± 1",
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
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadFrom",
            "value": 25,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 10,
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
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFull",
            "value": 156,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 66,
            "range": "± 2",
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
            "value": 44,
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
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_GetFrom",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo_BadLength",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_GetFrom",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/AddTo",
            "value": 34,
            "range": "± 1",
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
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_AddTo",
            "value": 40,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_GetFrom",
            "value": 23,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 1531,
            "range": "± 52",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 3644,
            "range": "± 112",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1439,
            "range": "± 83",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1158,
            "range": "± 54",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 253,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 260,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 579,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 300,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1315,
            "range": "± 71",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 1034,
            "range": "± 41",
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
            "value": 24,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/AddTo",
            "value": 30,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddTo",
            "value": 27,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 30,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 229506,
            "range": "± 8253",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 293501,
            "range": "± 16012",
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
          "id": "fd55c3621f9a9698b9dec4d366ec4b16d87a0e79",
          "message": "Merge pull request #45 from Brainwires/conf/train-8\n\nConformance train 8",
          "timestamp": "2026-11-23T01:15:39-06:00",
          "tree_id": "6e49e66b33aa2f3195ed61db8aea4e32926992ce",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/fd55c3621f9a9698b9dec4d366ec4b16d87a0e79"
        },
        "date": 1795419139472,
        "tool": "cargo",
        "benches": [
          {
            "name": "Benchmark MarshalTo",
            "value": 20,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 130,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Marshal",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 88,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport MarshalTo",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Marshal",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 88,
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
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 62,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack MarshalTo",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Marshal",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 81,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 27,
            "range": "± 1",
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
            "value": 52,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 72,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 138,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 171,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 38,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 41,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 42,
            "range": "± 1",
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
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 67,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 48,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_GetFrom",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_AddTo",
            "value": 46,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 192,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 133,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 215,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 211,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 34,
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
            "value": 24,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 9,
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
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFull",
            "value": 154,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 65,
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
            "value": 46,
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
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 24,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_GetFrom",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 31,
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
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/AddTo",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXOR",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_AddTo",
            "value": 40,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_GetFrom",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 1597,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 3394,
            "range": "± 36",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1323,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1114,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 219,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 268,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 559,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 340,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1346,
            "range": "± 38",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 1092,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkIsChannelData",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Encode",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Decode",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/AddTo",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddTo",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 219999,
            "range": "± 1334",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 219164,
            "range": "± 3669",
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
          "id": "0a063e6e6f10ebd47961f91dae50bb2d1d71b94a",
          "message": "Merge pull request #46 from Brainwires/conf/train-9\n\nConformance train 9",
          "timestamp": "2026-11-23T05:48:09-06:00",
          "tree_id": "3e57fc2a9c5616edde12e6c7b61287c882bb749c",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/0a063e6e6f10ebd47961f91dae50bb2d1d71b94a"
        },
        "date": 1795435526589,
        "tool": "cargo",
        "benches": [
          {
            "name": "Benchmark MarshalTo",
            "value": 27,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 48,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 149,
            "range": "± 20",
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
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 109,
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
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 106,
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
            "value": 72,
            "range": "± 1",
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
            "value": 25,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 87,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 98,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 66,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 110,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 206,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 201,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 46,
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
            "value": 50,
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
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 77,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 59,
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
            "value": 42,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 249,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 172,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 259,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 250,
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
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 12,
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
            "value": 194,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 78,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_WriteHeader",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_CloneTo",
            "value": 59,
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
            "value": 36,
            "range": "± 1",
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
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 39,
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
            "value": 1934,
            "range": "± 104",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 4598,
            "range": "± 69",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1548,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1295,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 283,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 326,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 684,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 414,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1399,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 1171,
            "range": "± 44",
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
            "value": 5,
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
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 252262,
            "range": "± 5173",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 281680,
            "range": "± 690",
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
          "id": "c51a4709100df8ffd8aa93f188ba87211e8c8876",
          "message": "Merge pull request #47 from Brainwires/conf/train-10\n\nConformance train 10 (release brainwires.6)",
          "timestamp": "2026-11-23T09:15:05-06:00",
          "tree_id": "fef077fd792af11e684719f64a664ee078c2e889",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/c51a4709100df8ffd8aa93f188ba87211e8c8876"
        },
        "date": 1795447898822,
        "tool": "cargo",
        "benches": [
          {
            "name": "Benchmark MarshalTo",
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 129,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Marshal",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 88,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport MarshalTo",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Marshal",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 88,
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
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 63,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack MarshalTo",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Marshal",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 82,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 27,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 97,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 52,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 72,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 139,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 170,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 38,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 40,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 41,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_GetNotFound",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Get",
            "value": 12,
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
            "value": 49,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_GetFrom",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_AddTo",
            "value": 47,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 190,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 133,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 216,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 211,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 34,
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
            "value": 24,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 9,
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
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFull",
            "value": 154,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 65,
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
            "value": 46,
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
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_GetFrom",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo_BadLength",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_GetFrom",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/AddTo",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXOR",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_AddTo",
            "value": 39,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_GetFrom",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 1498,
            "range": "± 92",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 3592,
            "range": "± 68",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1331,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1111,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 219,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 264,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 560,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 331,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1195,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 1041,
            "range": "± 37",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkIsChannelData",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Encode",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Decode",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/AddTo",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddTo",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 219948,
            "range": "± 1903",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 219217,
            "range": "± 947",
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
          "id": "e135fc95097f1bb868e5d251bd064b29ed0b4fc3",
          "message": "Merge pull request #49 from Brainwires/ci/agent-test-workflow\n\nci: agent-test, a hand-started test run on a GitHub-hosted runner",
          "timestamp": "2026-11-23T12:02:56-06:00",
          "tree_id": "7380b62b9a5c86dc124282937f8d3358ba37997f",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/e135fc95097f1bb868e5d251bd064b29ed0b4fc3"
        },
        "date": 1795457980949,
        "tool": "cargo",
        "benches": [
          {
            "name": "Benchmark MarshalTo",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 36,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 129,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Marshal",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 88,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport MarshalTo",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Marshal",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 90,
            "range": "± 4",
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
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 62,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack MarshalTo",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Marshal",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 80,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 11,
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
            "value": 52,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 73,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 141,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 170,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 38,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 40,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 41,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_GetNotFound",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Get",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 66,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 48,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_GetFrom",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_AddTo",
            "value": 47,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 189,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 131,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 216,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 228,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 34,
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
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadFrom",
            "value": 25,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 9,
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
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFull",
            "value": 153,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 64,
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
            "value": 46,
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
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_GetFrom",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo_BadLength",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_GetFrom",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/AddTo",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXOR",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_AddTo",
            "value": 39,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_GetFrom",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 1489,
            "range": "± 74",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 3534,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1342,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1113,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 222,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 263,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 569,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 350,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1215,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 1082,
            "range": "± 27",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkIsChannelData",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Encode",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Decode",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/AddTo",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddTo",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 219669,
            "range": "± 10149",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 219366,
            "range": "± 537",
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
          "id": "52d584f528c7f6cb2bb887e55927b5abe8755829",
          "message": "Merge pull request #48 from Brainwires/conf/train-11\n\nConformance train 11",
          "timestamp": "2026-11-23T13:32:45-06:00",
          "tree_id": "a3e5111773d79e292bfafd2880d00615097f0acd",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/52d584f528c7f6cb2bb887e55927b5abe8755829"
        },
        "date": 1795463377628,
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
            "value": 49,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 149,
            "range": "± 3",
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
            "value": 34,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 107,
            "range": "± 2",
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
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 106,
            "range": "± 3",
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
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 74,
            "range": "± 3",
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
            "value": 82,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 97,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 65,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 109,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 209,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 203,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 46,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 50,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 52,
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
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 79,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 59,
            "range": "± 1",
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
            "value": 60,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 42,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 252,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 170,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 258,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 252,
            "range": "± 4",
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
            "value": 36,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 13,
            "range": "± 3",
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
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 82,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_WriteHeader",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_CloneTo",
            "value": 59,
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
            "value": 36,
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
            "value": 40,
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
            "value": 36,
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
            "value": 48,
            "range": "± 1",
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
            "value": 2042,
            "range": "± 44",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 5413,
            "range": "± 102",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1555,
            "range": "± 37",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1293,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 279,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 315,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 680,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 412,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1386,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 1173,
            "range": "± 9",
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
            "value": 5,
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
            "value": 38,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddTo",
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 37,
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
            "value": 252919,
            "range": "± 3105",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 282008,
            "range": "± 2882",
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
          "id": "81e2253e1672d22f90ba0ffaf25aeb0ef8f2fa2c",
          "message": "Merge pull request #51 from Brainwires/conf/train-12\n\nConformance train 12",
          "timestamp": "2026-11-23T15:17:02-06:00",
          "tree_id": "81379680720055511d2bada998811240258fafd1",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/81e2253e1672d22f90ba0ffaf25aeb0ef8f2fa2c"
        },
        "date": 1795469545466,
        "tool": "cargo",
        "benches": [
          {
            "name": "Benchmark MarshalTo",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 24,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 107,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Marshal",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 68,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport MarshalTo",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Marshal",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 67,
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
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 45,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack MarshalTo",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Marshal",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 51,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 68,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 46,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 125,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 135,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 24,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 25,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_GetNotFound",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Get",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_GetFrom",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_AddTo",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 124,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 87,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 176,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 163,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 21,
            "range": "± 1",
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
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadFrom",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 6,
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
            "value": 10,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFull",
            "value": 92,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 34,
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
            "value": 29,
            "range": "± 2",
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
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo_BadLength",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_GetFrom",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/AddTo",
            "value": 16,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/GetFrom",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXOR",
            "value": 17,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_AddTo",
            "value": 21,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_GetFrom",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 944,
            "range": "± 78",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 2850,
            "range": "± 122",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1053,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 882,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 170,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 185,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 439,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 261,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 863,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 713,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkIsChannelData",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Encode",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Decode",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/AddTo",
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddTo",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 8,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 179765,
            "range": "± 1189",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 138458,
            "range": "± 5624",
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
          "id": "df82663c6ca0a346e485b6ea79025c793a43f9a8",
          "message": "Merge pull request #52 from Brainwires/conf/train-13\n\nConformance train 13",
          "timestamp": "2026-11-23T19:03:44-06:00",
          "tree_id": "9134dbc1669272dfc3f584921369e905bd0bc0cb",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/df82663c6ca0a346e485b6ea79025c793a43f9a8"
        },
        "date": 1795483252589,
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
            "value": 49,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 150,
            "range": "± 1",
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
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 107,
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
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 106,
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
            "value": 73,
            "range": "± 1",
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
            "value": 81,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 97,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 66,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 89,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 173,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 202,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 46,
            "range": "± 1",
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
            "value": 51,
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
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 76,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 58,
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
            "value": 61,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 42,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 255,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 173,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 258,
            "range": "± 1",
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
            "value": 42,
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
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 13,
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
            "value": 195,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 78,
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
            "value": 58,
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
            "value": 36,
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
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 42,
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
            "value": 39,
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
            "value": 1846,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 5476,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1579,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1278,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 280,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 313,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 683,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 418,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1369,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 1166,
            "range": "± 4",
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
            "value": 5,
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
            "value": 36,
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
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 33,
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
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 253022,
            "range": "± 7276",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 281893,
            "range": "± 2081",
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
          "id": "4431dda0dc88dfb5ccefd079e256bbf5d238a0d0",
          "message": "Merge pull request #53 from Brainwires/conf/train-14\n\nConformance train 14",
          "timestamp": "2026-11-23T19:33:10-06:00",
          "tree_id": "4d08019aa5eb6e7d86198a2bc93ee7bcb2d1c6f0",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/4431dda0dc88dfb5ccefd079e256bbf5d238a0d0"
        },
        "date": 1795484962568,
        "tool": "cargo",
        "benches": [
          {
            "name": "Benchmark MarshalTo",
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 128,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Marshal",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 88,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport MarshalTo",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Marshal",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 88,
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
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 62,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack MarshalTo",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Marshal",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 75,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 12,
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
            "value": 82,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 52,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 72,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 141,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 173,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 39,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 40,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 41,
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
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 64,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 48,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_GetFrom",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_AddTo",
            "value": 47,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 190,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 133,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 217,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 212,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 34,
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
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadFrom",
            "value": 24,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 9,
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
            "value": 11,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFull",
            "value": 154,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 65,
            "range": "± 1",
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
            "value": 45,
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
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_GetFrom",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo_BadLength",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_GetFrom",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/AddTo",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXOR",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_AddTo",
            "value": 39,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_GetFrom",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 1478,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 4099,
            "range": "± 52",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1325,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1110,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 218,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 264,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 560,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 347,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1280,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 1089,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkIsChannelData",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Encode",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Decode",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/AddTo",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddTo",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 219380,
            "range": "± 626",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 219024,
            "range": "± 2604",
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
          "id": "9ac196677a99f3310eae5047eddc71f6cee754ad",
          "message": "Merge pull request #54 from Brainwires/conf/train-15\n\nConformance train 15",
          "timestamp": "2026-11-24T01:27:06-06:00",
          "tree_id": "b9f4a4ec16974bf48381dc3cdcf82b7870ca812d",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/9ac196677a99f3310eae5047eddc71f6cee754ad"
        },
        "date": 1795506238266,
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
            "value": 50,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 150,
            "range": "± 1",
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
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 107,
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
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 106,
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
            "value": 72,
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
            "value": 81,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 98,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 66,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 90,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 179,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 202,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 45,
            "range": "± 0",
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
            "value": 51,
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
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 76,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 58,
            "range": "± 1",
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
            "value": 60,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 42,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 247,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 173,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 258,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 252,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 42,
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
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 13,
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
            "value": 194,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 78,
            "range": "± 1",
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
            "value": 57,
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
            "value": 36,
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
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 40,
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
            "value": 22,
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
            "value": 1897,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 5356,
            "range": "± 119",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1565,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1278,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 283,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 315,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 678,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 411,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1389,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 1178,
            "range": "± 9",
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
            "value": 5,
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
            "value": 36,
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
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 252311,
            "range": "± 6363",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 281456,
            "range": "± 2446",
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
          "id": "05375e98e32d966627beef1590110763af831f5b",
          "message": "Merge pull request #55 from Brainwires/conf/train-16\n\nConformance train 16",
          "timestamp": "2026-11-24T03:04:47-06:00",
          "tree_id": "279c18871cfe6ac0e2bdac29f7d063856edfe631",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/05375e98e32d966627beef1590110763af831f5b"
        },
        "date": 1795512084853,
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
            "value": 49,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 150,
            "range": "± 1",
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
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 107,
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
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 105,
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
            "value": 72,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack MarshalTo",
            "value": 5,
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
            "value": 85,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 97,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 67,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 108,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 209,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 207,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 46,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 49,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 51,
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
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 76,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 58,
            "range": "± 1",
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
            "value": 63,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 42,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 250,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 173,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 257,
            "range": "± 1",
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
            "range": "± 1",
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
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 14,
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
            "value": 195,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 78,
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
            "value": 58,
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
            "value": 37,
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
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 40,
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
            "value": 19,
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
            "value": 1949,
            "range": "± 76",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 5349,
            "range": "± 85",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1549,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1287,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 279,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 314,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 681,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 414,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1417,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 1198,
            "range": "± 15",
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
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Decode",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/AddTo",
            "value": 36,
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
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 251825,
            "range": "± 2757",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 281551,
            "range": "± 1293",
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
          "id": "4e6de2564ba6b788586cd7125b52af30c9b5ca16",
          "message": "Merge pull request #56 from Brainwires/conf/train-17\n\nConformance train 17",
          "timestamp": "2026-11-24T03:37:14-06:00",
          "tree_id": "f983d31f4f869c6e56c101fb10c5073bb29a20c6",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/4e6de2564ba6b788586cd7125b52af30c9b5ca16"
        },
        "date": 1795514031734,
        "tool": "cargo",
        "benches": [
          {
            "name": "Benchmark MarshalTo",
            "value": 26,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 48,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 151,
            "range": "± 4",
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
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 108,
            "range": "± 4",
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
            "value": 32,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 106,
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
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 73,
            "range": "± 1",
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
            "value": 26,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 81,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 97,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 66,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 88,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 174,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 202,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 49,
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
            "value": 51,
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
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 76,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 58,
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
            "value": 61,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 42,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 247,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 172,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 260,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 253,
            "range": "± 2",
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
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 13,
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
            "value": 195,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 78,
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
            "value": 59,
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
            "value": 37,
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
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 40,
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
            "value": 22,
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
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 1917,
            "range": "± 35",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 5458,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1551,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1284,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 281,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 318,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 686,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 411,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1375,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 1194,
            "range": "± 20",
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
            "value": 5,
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
            "range": "± 1",
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
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 34,
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
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 252397,
            "range": "± 1319",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 281869,
            "range": "± 3727",
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
          "id": "56b6476b345215d3ab44ace542477c0cdf3de01f",
          "message": "Merge pull request #58 from Brainwires/conf/train-19\n\nConformance train 19",
          "timestamp": "2026-11-24T05:06:56-06:00",
          "tree_id": "8066835b53d7e3ae42298e5cc9cb8a70e9eab5a2",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/56b6476b345215d3ab44ace542477c0cdf3de01f"
        },
        "date": 1795519384963,
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
            "value": 44,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 161,
            "range": "± 4",
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
            "value": 102,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport MarshalTo",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Marshal",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 100,
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
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 72,
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
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 81,
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
            "value": 107,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 61,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 84,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 186,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 200,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 40,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 44,
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
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Get",
            "value": 12,
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
            "value": 49,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_GetFrom",
            "value": 24,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_AddTo",
            "value": 49,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 215,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 149,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 277,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 259,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 36,
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
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadFrom",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 10,
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
            "value": 178,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 70,
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
            "value": 48,
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
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_GetFrom",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 32,
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
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/AddTo",
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/GetFrom",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXOR",
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_AddTo",
            "value": 40,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_GetFrom",
            "value": 23,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 1671,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 4880,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1587,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1305,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 254,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 295,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 665,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 384,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1463,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 1155,
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
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/AddTo",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddTo",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 25,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 275434,
            "range": "± 3573",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 309872,
            "range": "± 2101",
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
          "id": "3bbd6cc1d005678d391bcb336b43e437d2c6913b",
          "message": "Merge pull request #59 from Brainwires/conf/train-20\n\nConformance train 20: rename to rtci, release 0.1.0",
          "timestamp": "2026-11-24T05:45:50-06:00",
          "tree_id": "90b9bcdccc3747c517badb641cd8074f553709e6",
          "url": "https://github.com/Brainwires/webrtc-rs-rtc/commit/3bbd6cc1d005678d391bcb336b43e437d2c6913b"
        },
        "date": 1795521749203,
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
            "value": 50,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 154,
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
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 107,
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
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 105,
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
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 74,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack MarshalTo",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Marshal",
            "value": 25,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 82,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 39,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 98,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 66,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 89,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 171,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 202,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 45,
            "range": "± 1",
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
            "value": 51,
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
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 78,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 64,
            "range": "± 2",
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
            "value": 60,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 42,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 249,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 174,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 259,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 259,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 42,
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
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 13,
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
            "value": 194,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 78,
            "range": "± 1",
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
            "value": 58,
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
            "value": 36,
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
            "value": 27,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 40,
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
            "value": 27,
            "range": "± 1",
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
            "value": 1867,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 5539,
            "range": "± 230",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1570,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1297,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 281,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 374,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 679,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 412,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1372,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 1157,
            "range": "± 6",
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
            "value": 5,
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
            "value": 33,
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
            "value": 251513,
            "range": "± 3227",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 281523,
            "range": "± 734",
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
          "id": "777e7458923bc8a02cd9793c1ac36737ee60c707",
          "message": "Merge pull request #60 from Brainwires/conf/train-21\n\nConformance train 21",
          "timestamp": "2026-11-24T08:09:48-06:00",
          "tree_id": "2e12aaefacef68581e0770cb7f6dd4e606f247bd",
          "url": "https://github.com/Brainwires/rtci/commit/777e7458923bc8a02cd9793c1ac36737ee60c707"
        },
        "date": 1795530383776,
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
            "value": 49,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 148,
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
            "value": 34,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 107,
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
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 105,
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
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 72,
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
            "value": 82,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 16,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Marshal",
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye Unmarshal",
            "value": 98,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 67,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 90,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 174,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 201,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 45,
            "range": "± 0",
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
            "value": 50,
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
            "value": 15,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 75,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 58,
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
            "value": 60,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 42,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 251,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 174,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 260,
            "range": "± 1",
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
            "value": 42,
            "range": "± 1",
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
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 13,
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
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFull",
            "value": 196,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 78,
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
            "value": 57,
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
            "value": 36,
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
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 41,
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
            "value": 25,
            "range": "± 1",
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
            "value": 1920,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 5535,
            "range": "± 155",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1548,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1291,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 277,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 313,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 679,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 417,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1392,
            "range": "± 54",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 1173,
            "range": "± 8",
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
            "value": 5,
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
            "value": 18,
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
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 37,
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
            "value": 251530,
            "range": "± 5412",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 281459,
            "range": "± 4334",
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
          "id": "3a2d95e63c6a9fce54d201bcdb50e2226275df71",
          "message": "Merge pull request #61 from Brainwires/conf/train-22\n\nConformance train 22",
          "timestamp": "2026-11-24T09:52:06-06:00",
          "tree_id": "3e62704fe1faac47598e53b1daf2d7150830d424",
          "url": "https://github.com/Brainwires/rtci/commit/3a2d95e63c6a9fce54d201bcdb50e2226275df71"
        },
        "date": 1795536513814,
        "tool": "cargo",
        "benches": [
          {
            "name": "Benchmark MarshalTo",
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 128,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Marshal",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 88,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport MarshalTo",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Marshal",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 87,
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
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 62,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack MarshalTo",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Marshal",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 77,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 12,
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
            "value": 81,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 52,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 73,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 141,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 171,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 38,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 40,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 41,
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
            "value": 12,
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
            "value": 49,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_GetFrom",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_AddTo",
            "value": 46,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 192,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 131,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 216,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 212,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 35,
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
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadFrom",
            "value": 25,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 10,
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
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFull",
            "value": 153,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 64,
            "range": "± 1",
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
            "value": 45,
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
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_GetFrom",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 29,
            "range": "± 1",
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
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/AddTo",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXOR",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_AddTo",
            "value": 39,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_GetFrom",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 1615,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 4158,
            "range": "± 72",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1336,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1112,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 218,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 259,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 559,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 342,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1202,
            "range": "± 38",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 1048,
            "range": "± 4",
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
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Decode",
            "value": 24,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/AddTo",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 14,
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
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 219929,
            "range": "± 953",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 219153,
            "range": "± 915",
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
          "id": "d7dcb9ab46fa23ab123fc976716031ba1a8fb378",
          "message": "Merge pull request #63 from Brainwires/conf/train-23\n\nConformance train 23",
          "timestamp": "2026-11-24T10:27:17-06:00",
          "tree_id": "74b73dc82a6f9504d098d835fb5dc5a38dbcc941",
          "url": "https://github.com/Brainwires/rtci/commit/d7dcb9ab46fa23ab123fc976716031ba1a8fb378"
        },
        "date": 1795538599598,
        "tool": "cargo",
        "benches": [
          {
            "name": "Benchmark MarshalTo",
            "value": 20,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 129,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport MarshalTo",
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Marshal",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SenderReport Unmarshal",
            "value": 88,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport MarshalTo",
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Marshal",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "ReceiverReport Unmarshal",
            "value": 87,
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
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "PictureLossIndication Unmarshal",
            "value": 64,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack MarshalTo",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Marshal",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "TransportLayerNack Unmarshal",
            "value": 78,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Goodbye MarshalTo",
            "value": 12,
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
            "value": 84,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription MarshalTo",
            "value": 52,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Marshal",
            "value": 72,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "SourceDescription Unmarshal",
            "value": 141,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Unmarshal",
            "value": 171,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Compound Marshal",
            "value": 38,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMappedAddress_AddTo",
            "value": 40,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkAlternateServer_AddTo",
            "value": 41,
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
            "value": 12,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCode_AddTo",
            "value": 65,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_AddTo",
            "value": 48,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkErrorCodeAttribute_GetFrom",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_AddTo",
            "value": 46,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkFingerprint_Check",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Build",
            "value": 192,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkBuildOverhead/Raw",
            "value": 130,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_AddTo",
            "value": 216,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageIntegrity_Check",
            "value": 221,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_Write",
            "value": 35,
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
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadFrom",
            "value": 24,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessage_ReadBytes",
            "value": 9,
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
            "value": 11,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFull",
            "value": 153,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkMessageFullHardcore",
            "value": 63,
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
            "value": 45,
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
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_AddTo",
            "value": 22,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUsername_GetFrom",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkNonce_AddTo",
            "value": 30,
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
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/AddTo",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkUnknownAttributes/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXOR",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_AddTo",
            "value": 40,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkXORMappedAddress_GetFrom",
            "value": 21,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Marshal",
            "value": 1621,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "Benchmark Unmarshal",
            "value": 3901,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP",
            "value": 1328,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP",
            "value": 1118,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTCP",
            "value": 218,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTCP",
            "value": 274,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Encrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 560,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Decrypt/RTP/AEAD-AES-128-GCM/ring",
            "value": 344,
            "range": "± 49",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AES-128-CM-HMAC-SHA1-80/ring",
            "value": 1242,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "SRTP/Setup/AEAD-AES-128-GCM/ring",
            "value": 1115,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkIsChannelData",
            "value": 1,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Encode",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelData_Decode",
            "value": 23,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/AddTo",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkChannelNumber/GetFrom",
            "value": 14,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddTo",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkData/AddToRaw",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/AddTo",
            "value": 30,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "BenchmarkLifetime/GetFrom",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Interleaved to Deinterleaved",
            "value": 219672,
            "range": "± 1935",
            "unit": "ns/iter"
          },
          {
            "name": "Media/Buffer/Deinterleaved to Interleaved",
            "value": 219170,
            "range": "± 810",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}