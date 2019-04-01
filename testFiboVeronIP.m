clear;

load "sha.m";

// ---------------------------------------------------------------------------

pFibonacci := function(p, n)
	if n eq 0 then // n = 0
		return 0;
	elif n ge 1 and n le p+1 then // 1 <= n <= p+1
		return 1;
	elif n gt p+1 then // n > p+1
		return $$(p, n-1) + $$(p, n-p-1);
	else // n < 0
		return $$(p, n+p+1) - $$(p, n+p);
	end if;
end function;

// ---------------------------------------------------------------------------

Qp_matrix_power := function(p,n)
	Q := ZeroMatrix(Integers(), p+1, p+1);
	for j in [0..p] do
		//0,j,pFibonacci(p,n-p-j);
		Q[1,j+1] := pFibonacci(p,n+1-j);
	end for;

	for i in [1..p] do
		for j in [0..p] do
			//i,j,pFibonacci(p,n-p+i-j);
			Q[i+1,j+1] := pFibonacci(p,n-p+i-j);
		end for;
	end for;

	return Q;
end function;

// ---------------------------------------------------------------------------

FibonacciWeight := function(A)
	w := 0;
	for i in [1..Nrows(A)] do
		for j in [1..Ncols(A)] do
			if A[i,j] ne 0 then
				w := w + 1;
			end if;
		end for;
	end for;

	return w;
end function;

// ---------------------------------------------------------------------------
 
RandomMessage := function(size, max)
  return Matrix(size,size,[Random(1,max) : i in [1..size^2]]);
end function;

// ---------------------------------------------------------------------------

RandomPermutation := function(n)
	L := [i : i in [1..n]];
	P := [];
	while L ne [] do
		ind := Random(1,#L);
		Append(~P, L[ind]);
		Remove(~L,ind);
	end while;

	return P;
end function;

// ---------------------------------------------------------------------------

GenerateRandomGammaSigma := function(p,l)
	Gamma1 := RandomPermutation(p+1);
	Gamma2 := RandomPermutation(p+1);
	Sigma := Matrix(Rationals(),p+1,p+1,[Random(1,2^l-1)/Random(1,2^l-1) : i in [1..(p+1)^2]]);

	return [*Gamma1,Gamma2,Sigma*];
end function;

// ---------------------------------------------------------------------------

Permutation2Hex := function(P)
// NOTE: 
// DECIDE IF ALL ELEMENT IN P MUST BE TRANSLATED 
// IN A STRING WITH FIXED NUMBER OF DIGITS
// LIKE 16 -> 10_hex then e.g. 10 -> 0A_hex instead in 10 -> A_hex
//
	s := "";
	for i in [1..#P] do
		s := s cat IntegerToString(P[i],16);
	end for;

	return s;
end function;

// ---------------------------------------------------------------------------

RationalMatriz2Hex := function(A)
	s := "";
	for i in [1..Nrows(A)] do
		for j in [1..Ncols(A)] do
			s := s cat IntegerToString(Numerator(A[i,j])) cat IntegerToString(Denominator(A[i,j]));
		end for;
	end for;

	return s;
end function;

// ---------------------------------------------------------------------------

ApplyGammaSigmaToMatrix := function(GammaSigma, A)

	Gamma1 := GammaSigma[1];
	Gamma2 := GammaSigma[2];
	Sigma  := GammaSigma[3];

	A_out := ZeroMatrix(Rationals(),Nrows(A),Ncols(A));
	for i in [1..Nrows(A)] do
		for j in [1..Ncols(A)] do
			A_out[i,j] := Sigma[Gamma1[i],Gamma2[j]] * A[Gamma1[i],Gamma2[j]];
		end for;
	end for;

	return A_out;
end function;

// ---------------------------------------------------------------------------

FibonacciKeyGen := function(PARAM)
	r := PARAM["r"];
	p := PARAM["p"];	
	n := PARAM["n"];
	l := PARAM["l"];	

	Q := Qp_matrix_power(p,n);

	// generate PRIVATE KEY
	// random message
	M := RandomMessage(p+1,2^r-1);
	// random error of weight p+1
	E_prime :=  Matrix(p+1,p+1,[Random(1,2^l-1) : i in [1..(p+1)^2]]);
	i := Random(1,p+1);
	j := Random(1,p+1);
	E_prime[i,j] := 0;

	// generate PUBLIC KEY
	// R := M*Q + E;
	R_tmp := M*Q;
	R := ZeroMatrix(Integers(),p+1,p+1);
	for i in [1..Nrows(R)] do
		for j in [1..Ncols(R)] do
			R[i,j] := (R_tmp[i,j] + E_prime[i,j]) mod 2^l; // could also be xor
		end for;
	end for;
	E := R-R_tmp;

	PRIV_KEY := AssociativeArray();
	PRIV_KEY["M"] := M; 
	PRIV_KEY["E"] := E;

	PUB_KEY := AssociativeArray();
	PUB_KEY["R"] := R;
	PUB_KEY["Q"] := Q;


	return PRIV_KEY, PUB_KEY;
end function;

// ---------------------------------------------------------------------------

ComputeC1 := function(gammasigma)
	gamma1 := gammasigma[1];
	gamma2 := gammasigma[2];
	sigma  := gammasigma[3];
 	gamma1_hex := Permutation2Hex(gamma1);
 	gamma2_hex := Permutation2Hex(gamma2);
 	sigma_hex  := RationalMatriz2Hex(sigma);
	c1 := Sha(gamma1_hex cat gamma2_hex cat sigma_hex ,256:MsgType:="hex");

	return c1;
end function;

// ---------------------------------------------------------------------------

ComputeC2 := function(gammasigma,U,Q)
	T := ApplyGammaSigmaToMatrix(gammasigma, U*Q );
	T_hex := RationalMatriz2Hex(T);
	c2 := Sha(T_hex,256:MsgType:="hex");

	return c2;
end function;

// ---------------------------------------------------------------------------

ComputeC3 := function(gammasigma,V1,Q,V2)
	T := ApplyGammaSigmaToMatrix(gammasigma, V1*Q+V2) ;
	T_hex := RationalMatriz2Hex(T);
	c3 := Sha(T_hex,256:MsgType:="hex");

	return c3;
end function;

// ---------------------------------------------------------------------------

// Paramters
r := 2; p := 10; n := 12; l := 6;
 
//t := Floor((n-k)/(2*lambda)); 
PARAM := AssociativeArray();
PARAM["r"] := r;
PARAM["p"] := p;
PARAM["n"] := n;
PARAM["l"] := l;


// Veron Identification Protocol
// -----------------------------

// KEY GENERATION

"\nPublic parameter:";
"r = ", r;
"p = ", p;
"n = ", n;
"l = ", l;


PRIV_KEY, PUB_KEY := FibonacciKeyGen(PARAM);

R := PUB_KEY["R"];
Q := PUB_KEY["Q"];

"Q_p^n = ", Q;

M := PRIV_KEY["M"];
E := PRIV_KEY["E"];

"\nPrivate key:";
"M = ", M;
"E = ", E;

"\nPublic key:";
"R = ", R;


// IDENTIFICATION PROTOCOL

// 1. COMMITMENT

U := RandomMessage(p+1,2^r-1);

GammaSigma := GenerateRandomGammaSigma(p,l);

c1 := ComputeC1(GammaSigma);

c2 := ComputeC2(GammaSigma,U+M,Q);

c3 := ComputeC3(GammaSigma,U,Q,R);

"\nCommitment:";
c1,c2,c3;

// 2. CHALLENGE
b := Random({0,1,2});
"\nChallenge:";
b;

// 3. RESPONSE
case b:
	when 0:
		response := [* GammaSigma, U+M *];
	when 1:
		tmp1 := ApplyGammaSigmaToMatrix(GammaSigma, (U+M)*Q);
		tmp2 := ApplyGammaSigmaToMatrix(GammaSigma, E);
		response := [* tmp1, tmp2 *];
	when 2:
		response := [* GammaSigma, U *];
end case;

"\nResponse:";
response;

// 4. CHECK
R := PUB_KEY["R"];
Q := PUB_KEY["Q"];


"\n";
case b:
	when 0:
		// check c1,c2
		if c1 eq ComputeC1(response[1])                and 
           c2 eq ComputeC2(response[1],response[2],Q)  then
			"IDENTIFICATION SUCCESS!";
		else
			"IDENTIFICATION FAILURE...";
		end if;
	when 1:
		// check c2,c3 and Weight(Gamma(Sigma(E))) == (p+1)^2-1

		// c2 ?= Hash(rsp1)
		T_hex := RationalMatriz2Hex(response[1]);
		h1 := Sha(T_hex,256:MsgType:="hex"); 

		// c3 ?= Hash(rsp1+rsp2)
		T_hex := RationalMatriz2Hex(response[1] + response[2]);
		h2 := Sha(T_hex,256:MsgType:="hex");

		if c2 eq h1                      and 
           c3 eq h2                      and
           FibonacciWeight(response[2]) eq (p+1)^2-1  then
			"IDENTIFICATION SUCCESS!";
		else
			"IDENTIFICATION FAILURE...";
		end if;
	when 2:
		// check c1,c3
		if c1 eq ComputeC1(response[1])                                  and 
           c3 eq ComputeC3(response[1],response[2],Q,R)  then
			"IDENTIFICATION SUCCESS!";
		else
			"IDENTIFICATION FAILURE...";
		end if;
end case;
