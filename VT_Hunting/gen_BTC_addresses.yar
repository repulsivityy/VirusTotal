import "vt"

rule btc_addresses_starting_by_1
{
  strings:
      $1a = /1a[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $1b = /1b[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $1c = /1c[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $1d = /1d[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $1e = /1e[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $1f = /1f[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $1g = /1g[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $1h = /1h[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $1i = /1i[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $1j = /1j[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $1k = /1k[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $1m = /1m[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $1n = /1n[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $1p = /1p[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $1q = /1q[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $1r = /1r[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $1s = /1s[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $1t = /1t[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $1u = /1u[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $1v = /1v[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $1w = /1w[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $1x = /1x[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $1y = /1y[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $1z = /1z[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $11 = /11[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $12 = /12[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $13 = /13[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $14 = /14[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $15 = /15[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $16 = /16[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $17 = /17[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $18 = /18[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $19 = /19[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
  condition:
  	   /* CONDITION 1 :
       Match only new files, avoid rescanned files */
       vt.metadata.new_file 
      and any of them
}

rule btc_addresses_starting_by_3
{
  strings:
      $3a = /3a[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $3b = /3b[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $3c = /3c[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $3d = /3d[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $3e = /3e[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $3f = /3f[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $3g = /3g[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $3h = /3h[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $3i = /3i[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $3j = /3j[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $3k = /3k[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $3m = /3m[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $3n = /3n[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $3p = /3p[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $3q = /3q[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $3r = /3r[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $3s = /3s[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $3t = /3t[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $3u = /3u[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $3v = /3v[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $3w = /3w[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $3x = /3x[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $3y = /3y[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $3z = /3z[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $31 = /31[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $32 = /32[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $33 = /33[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $34 = /34[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $35 = /35[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $36 = /36[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $37 = /37[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $38 = /38[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
      $39 = /39[a-km-zA-HJ-NP-Z1-9]{24,33}/ nocase
  condition:
  	   /* Match only new files to avoid rescanned files */
       vt.metadata.new_file 
      and any of them
}

rule btc_addresses_starting_by_bc1
{
  strings:
      $bc1a = /bc1a[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc1b = /bc1b[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc1c = /bc1c[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc1d = /bc1d[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc1e = /bc1e[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc1f = /bc1f[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc1g = /bc1g[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc1h = /bc1h[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc1i = /bc1i[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc1j = /bc1j[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc1k = /bc1k[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc1m = /bc1m[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc1n = /bc1n[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc1p = /bc1p[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc1q = /bc1q[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc1r = /bc1r[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc1s = /bc1s[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc1t = /bc1t[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc1u = /bc1u[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc1v = /bc1v[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc1w = /bc1w[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc1x = /bc1x[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc1y = /bc1y[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc1z = /bc1z[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc11 = /bc11[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc12 = /bc12[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc13 = /bc13[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc14 = /bc14[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc15 = /bc15[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc16 = /bc16[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc17 = /bc17[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc18 = /bc18[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
      $bc19 = /bc19[a-km-zA-HJ-NP-Z1-9]{22,31}/ nocase
  condition:
  	   /* CONDITION 1 :
       Match only new files, avoid rescanned files */
       vt.metadata.new_file 
      and any of them
}