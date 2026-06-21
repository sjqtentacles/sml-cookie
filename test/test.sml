(* test.sml -- sml-cookie tests against RFC 6265 examples. *)

structure CookieTests =
struct
  open Harness

  fun run () =
    let
      (* ---- parseCookie (request header) ---- *)
      val () = section "parseCookie"
      val () = checkStringList "names"
        (["SID", "lang"],
         List.map #1 (Cookie.parseCookie "SID=31d4d96e407aad42; lang=en-US"))
      val () = checkStringList "values"
        (["31d4d96e407aad42", "en-US"],
         List.map #2 (Cookie.parseCookie "SID=31d4d96e407aad42; lang=en-US"))
      val () = checkInt "single pair" (1, List.length (Cookie.parseCookie "a=b"))
      val () = checkInt "empty" (0, List.length (Cookie.parseCookie ""))
      val () = checkString "valueless"
        ("", #2 (hd (Cookie.parseCookie "flag")))

      (* ---- build (Set-Cookie) ---- *)
      val () = section "build"
      val () = checkString "bare"
        ("SID=31d4d96e407aad42", Cookie.build (Cookie.cookie "SID" "31d4d96e407aad42"))
      val full =
        { name = "SID", value = "31d4d96e407aad42"
        , path = SOME "/", domain = SOME "example.com"
        , maxAge = NONE, expires = NONE
        , secure = true, httpOnly = true, sameSite = SOME Cookie.Lax }
      val () = checkString "with attributes"
        ("SID=31d4d96e407aad42; Path=/; Domain=example.com; Secure; HttpOnly; SameSite=Lax",
         Cookie.build full)
      val () = checkString "max-age"
        ("x=y; Max-Age=3600",
         Cookie.build { name = "x", value = "y", path = NONE, domain = NONE
                      , maxAge = SOME 3600, expires = NONE, secure = false
                      , httpOnly = false, sameSite = NONE })

      (* ---- httpDate ---- *)
      val () = section "httpDate"
      (* RFC 7231 example: Sun, 06 Nov 1994 08:49:37 GMT *)
      val () = checkString "imf-fixdate"
        ("Sun, 06 Nov 1994 08:49:37 GMT",
         Cookie.httpDate { year = 1994, month = 11, day = 6 } (8, 49, 37))
      val () = checkString "expires in build"
        ("s=1; Expires=Sun, 06 Nov 1994 08:49:37 GMT",
         Cookie.build { name = "s", value = "1", path = NONE, domain = NONE
                      , maxAge = NONE
                      , expires = SOME (Cookie.httpDate { year = 1994, month = 11, day = 6 } (8, 49, 37))
                      , secure = false, httpOnly = false, sameSite = NONE })

      (* ---- parseSetCookie ---- *)
      val () = section "parseSetCookie"
      val sc = valOf (Cookie.parseSetCookie
        "SID=31d4d96e407aad42; Path=/; Domain=example.com; Max-Age=3600; Secure; HttpOnly; SameSite=Strict")
      val () = checkString "name" ("SID", #name sc)
      val () = checkString "value" ("31d4d96e407aad42", #value sc)
      val () = checkString "path" ("/", valOf (#path sc))
      val () = checkString "domain" ("example.com", valOf (#domain sc))
      val () = checkInt "max-age" (3600, valOf (#maxAge sc))
      val () = checkBool "secure" (true, #secure sc)
      val () = checkBool "httpOnly" (true, #httpOnly sc)
      val () = checkBool "samesite strict"
        (true, #sameSite sc = SOME Cookie.Strict)
      val () = checkBool "no expires" (true, #expires sc = NONE)
      val () = checkBool "missing name=val rejected"
        (true, not (isSome (Cookie.parseSetCookie "Secure; HttpOnly")))

      (* round-trip *)
      val () = checkString "build/parse round-trip"
        (Cookie.build full, Cookie.build (valOf (Cookie.parseSetCookie (Cookie.build full))))

      (* ---- signed cookies ---- *)
      val () = section "signed"
      val key = "secret-key"
      val signed = SignedCookie.sign { key = key, name = "auth", value = "user-42" }
      val () = checkString "signed cookie name" ("auth", #name signed)
      val () = checkBool "signed value differs from plain"
        (true, #value signed <> "user-42")
      val pairs = Cookie.parseCookie (Cookie.build signed)
      val () = checkString "read back signed value"
        ("user-42", valOf (SignedCookie.read { key = key, name = "auth" } pairs))
      val () = checkBool "wrong key rejected"
        (true, not (isSome (SignedCookie.read { key = "other", name = "auth" } pairs)))
      val () = checkBool "absent cookie -> NONE"
        (true, not (isSome (SignedCookie.read { key = key, name = "missing" } pairs)))
      (* tamper: flip a char in the payload portion *)
      val tampered = List.map (fn (k, v) =>
                       if k = "auth"
                       then (k, "X" ^ String.extract (v, 1, NONE))
                       else (k, v)) pairs
      val () = checkBool "tampered token rejected"
        (true, not (isSome (SignedCookie.read { key = key, name = "auth" } tampered)))
    in
      ()
    end
end
