#include <stdint.h>
#include <stdlib.h>
#include <iostream>
#include "sha1.h"
#include "bignum.h"
#include <math.h>
#include <time.h>

using namespace std;
BigNum m,p,q,g,r,s,y,One;

//DSS verification algorithm
void verify(BigNum r,BigNum s)
{
  BigNum w,v_h,u1,u2,v,v_r,v_s;
  string v_h_str,v_r_str,v_s_str,v_digest;
  cout <<"\nEnter message : ";
  cin>>v_h_str;
  cout <<"\nEnter r : ";
  cin>>v_r_str;
  cout <<"\nEnter s : ";
  cin>>v_s_str;

  v_h = StringToArray(v_h_str);
  //cout << "sha1('grape'):" << sha1("grape") << endl;
  v_digest = sha1(v_h_str); 
  v_h = Add(v_h,StringToArray(v_digest));
   
  v_r = StringToArray(v_r_str);
  v_s = StringToArray(v_s_str);

  w = Inverse(v_s,q);
  u1 = PwrMod(Mul(v_h,w),One,q);
  u2 = PwrMod(Mul(v_r,w),One,q);
  v = PwrMod((PwrMod(Mul(PwrMod(g,u1,p),PwrMod(y,u2,p)),One,p)),One,q);
  string v_str;
  v_str = value_number(v);
  
  if(v_str.compare(v_r_str)==0)
    cout<<"\n Verification Successful!!";
  else
    cout<<"\n Verification Failed!!";
}

//DSS signing algorithm
void signature_gen(BigNum x)
{
  BigNum k,HM;
  string HM_str,k_str,r_str,s_str,digest;
  cout <<"\nEnter message : ";
  cin>>HM_str;
  //cout << "sha1('grape'):" << sha1("grape") << endl;
  HM = StringToArray(HM_str);
  digest = sha1(HM_str);
  HM = Add(HM,StringToArray(digest));

  do{
    k = PwrMod(StringToArray(to_string(rand())),One,q);
    k_str = value_number(k);
  }while(k_str.compare("")==0 | !Compare(k,q));

  r = PwrMod(PwrMod(g,k,p),One,q);
  s = PwrMod(Mul(Inverse(k,q),Add(HM,Mul(x,r))),One,q);

  r_str = value_number(r);
  s_str = value_number(s);
  if(r_str.compare("")==0)
    r_str = "0";
  if(s_str.compare("")==0)
    s_str = "0";
  cout<<"\n\nDigital signature is :";
  cout<<"\n\tr="<<r_str;
  cout<<"\n\ts="<<s_str;
}

int main()
{
  BigNum h,x;
  string h_str,g_str,y_str,x_str;
  One.Num[0] = 1;
  srand (time(NULL));
  p = StringToArray("5533560204899578487112594480354737234891979899692379913185949648481993669656140225694297567305628143");
  q = StringToArray("2766780102449789243556297240177368617445989949846189956592974824240996834828070112847148783652814071");
  DivResult DR;
  DR = DivLarge(Sub(p,One),q);
 
  do{//choose random h ; 1<h<p-1
    h = PwrMod(StringToArray(to_string(rand())),One,Sub(p,StringToArray("2")));
    h_str = value_number(h);
  }while(h_str.compare("1")==0 || h_str.compare("")==0);

  g = PwrMod(h,DR.Result,p);
  g_str = value_number(g);

  do{//random x b/w 0 < x <q
    x = PwrMod(StringToArray(to_string(rand())),One,Sub(q,One));
    x_str = value_number(x);
  }while(x_str.compare("")==0);

  y = PwrMod(g,x,p);//public key gen
  y_str = value_number(y);

  if(g_str.compare("")==0)
    g_str = "0";
  if(y_str.compare("")==0)
    y_str = "0";
  cout<<"\nPublic key is";
  cout<<"\n\tp="<<value_number(p);
  cout<<"\n\tq="<<value_number(q);
  cout<<"\n\tg="<<g_str;
  cout<<"\n\ty="<<y_str;
  cout<<"\n\nPrivate key is";
  cout<<"\n\tx="<<x_str;

  int mode;
  while(1){
    cout<<"\n\nSelect the Mode: 1.Signature Generation 2.Verify Signature 3)Exit\n";
    cin>>mode;
    switch(mode) {
      case 1: {
        signature_gen(x);
        break; }
      case 2: {
        verify(r,s);
        break; }
      case 3: {
        goto exit; }
      default: {
        cout<<("\nInvalid Mode! Enter a valid Mode to continue\n"); }
    }
  }
  exit:
  return 0;
}
