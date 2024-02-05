rule CoinMiner_Strings : SCRIPT HIGHVOL {
   meta:
      description = "Detects mining pool protocol string in Executable"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      reference = "https://minergate.com/faq/what-pool-address"
      date = "2018-01-04"
      modified = "2021-10-26"
      nodeepdive = 1
      id = "ac045f83-5f32-57a9-8011-99a2658a0e05"
   strings:
      $sa1 = "stratum+tcp://" ascii
      $sa2 = "stratum+udp://" ascii
      $sb1 = "\"normalHashing\": true,"
   condition:
      filesize < 3000KB and 1 of them
}

rule PUA_CryptoMiner_Jan19_1 {
   meta:
      description = "Detects Crypto Miner strings"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-01-31"
      score = 80
      hash1 = "ede858683267c61e710e367993f5e589fcb4b4b57b09d023a67ea63084c54a05"
      id = "aebfdce9-c2dd-5f24-aa25-071e1a961239"
   strings:
      $s1 = "Stratum notify: invalid Merkle branch" fullword ascii
      $s2 = "-t, --threads=N       number of miner threads (default: number of processors)" fullword ascii
      $s3 = "User-Agent: cpuminer/" ascii
      $s4 = "hash > target (false positive)" fullword ascii
      $s5 = "thread %d: %lu hashes, %s khash/s" fullword ascii
   condition:
      filesize < 1000KB and 1 of them
}