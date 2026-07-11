(* demo.sml - RFC 6265 cookie build/parse and HMAC-signed cookie round-trip.
   Deterministic: no wall-clock, no unseeded randomness, no environment reads. *)

structure C = Cookie
structure S = SignedCookie

fun sameSiteToString ssOpt =
  case ssOpt of
      NONE => "-"
    | SOME C.Strict => "Strict"
    | SOME C.Lax => "Lax"
    | SOME C.None => "None"

fun optOr d s = Option.getOpt (s, d)
fun optIntOr d n = case n of SOME i => Int.toString i | NONE => d

val () = print "sml-cookie demo\n"

val () = print "\nBare cookie:\n"
val bare = C.cookie "SID" "31d4d96e407aad42"
val () = print ("  " ^ C.build bare ^ "\n")

val () = print "\nFully-attributed cookie:\n"
val full =
  { name = "SID", value = "31d4d96e407aad42"
  , path = SOME "/", domain = SOME "example.com"
  , maxAge = SOME 3600, expires = NONE
  , secure = true, httpOnly = true, sameSite = SOME C.Lax }
val fullStr = C.build full
val () = print ("  " ^ fullStr ^ "\n")

val () = print "\nRound-trip via parseSetCookie:\n"
val () =
  case C.parseSetCookie fullStr of
      NONE => print "  parse failed\n"
    | SOME sc =>
        print ("  name=" ^ #name sc ^ " value=" ^ #value sc
               ^ " path=" ^ optOr "-" (#path sc)
               ^ " domain=" ^ optOr "-" (#domain sc)
               ^ " maxAge=" ^ optIntOr "-" (#maxAge sc)
               ^ " secure=" ^ Bool.toString (#secure sc)
               ^ " httpOnly=" ^ Bool.toString (#httpOnly sc)
               ^ " sameSite=" ^ sameSiteToString (#sameSite sc) ^ "\n")

val () = print "\nExpires formatted as an IMF-fixdate:\n"
val expiresDate : DateTime.date = { year = 1994, month = 11, day = 6 }
val () = print ("  " ^ C.httpDate expiresDate (8, 49, 37) ^ "\n")

val () = print "\nSigned cookie round-trip:\n"
val key = "my-secret-key"
val signed = S.sign { key = key, name = "auth", value = "user-42" }
val () = print ("  Set-Cookie: " ^ C.build signed ^ "\n")
val pairs = C.parseCookie (#name signed ^ "=" ^ #value signed)
val () =
  case S.read { key = key, name = "auth" } pairs of
      SOME v => print ("  verified value = " ^ v ^ "\n")
    | NONE => print "  verification failed\n"

val () = print "\nTamper detection:\n"
val tampered =
  List.map (fn (n, v) => if n = "auth" then (n, v ^ "x") else (n, v)) pairs
val () =
  case S.read { key = key, name = "auth" } tampered of
      SOME v => print ("  unexpectedly verified: " ^ v ^ "\n")
    | NONE => print "  tampered cookie rejected (NONE)\n"
