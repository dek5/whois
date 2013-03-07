/**
 * Created with IntelliJ IDEA.
 * User: eugene
 * Date: 15.08.12
 * Time: 15:00
 * To change this template use File | Settings | File Templates.
 */

/**
 * Created with IntelliJ IDEA.
 * User: eugene
 * Date: 06.08.12
 * Time: 18:18
 * To change this template use File | Settings | File Templates.
 */

import scala.xml.XML

object whois {
  /*
    val xml = XML.load("https://apps.db.ripe.net/whois/search.xml?query-string=95.188.50.5&source=ripe")
         <attribute value="95.188.32.0 - 95.188.63.255" name="inetnum"></attribute>
         <attribute value="WEBSTREAM" name="netname"></attribute>

    val inetnum=(xml \\ "objects" \\ "attributes" \ "attribute")(0) \ "@value"
    inetnum: scala.xml.NodeSeq = 95.188.32.0 - 95.188.63.255

    val netname=(xml \\ "objects" \\ "attributes" \ "attribute")(1) \ "@value"
    netname: scala.xml.NodeSeq = WEBSTREAM



  for {i<-addr.toString.split("[ -]+")} println(i)
  95.188.32.0
  95.188.63.255


    scala> val adnum = for {ad <- lll.split('.')} yield ad.toInt
  adnum: Array[Int] = Array(95, 188, 32, 0)



  val abc=List.iterate(1,4)(_*256).reverse
  abc: List[Int] = List(16777216, 65536, 256, 1)



    val adddr=Array(95, 188, 32, 0)
    (adddr,List.range(0,adddr.length).reverse).zipped.map((x,y)=>x*math.pow(256,y).toInt).sum


    val validIp="""(\d+)\.(\d+)\.(\d+)\.(\d+)""".r
    scala> validIp findFirstIn "2.2.2"
    res8: Option[String] = None

    scala> validIp findFirstIn "2.2.2.2"
    res9: Option[String] = Some(2.2.2.2)


  */
  def queryRipe(ipAddr: String): Map[String, String] = {
    val answer = XML.load("https://apps.db.ripe.net/whois/search.xml?query-string=" + ipAddr + "&source=ripe")
    val inetNum = ((answer \\ "objects" \\ "attributes" \ "attribute")(0) \ "@value").toString()
    val netName = ((answer \\ "objects" \\ "attributes" \ "attribute")(1) \ "@value").toString()
    val addrs = inetNum.split("[ -]+")
    Map("netname" -> netName, "addrDown" -> addrs(0), "addrUp" -> addrs(1))
  }

  def ipToInt(ipAddr: String): Int = {
    val octets = for {octet <- ipAddr.split('.')} yield octet.toInt
    (octets.reverse, List.iterate(1, octets.length)(_ * 256)).zipped.map(_ * _).sum
  }

  def main(args: Array[String]) {
    if (args.length == 0) {
      println("Specify an IP address to check!")
      System.exit(-1);
    }
    val validIP = """(\d+)\.(\d+)\.(\d+)\.(\d+)""".r

    def abort() {
      println("Invalid IP address!"); System.exit(-2)
    }

    val ip = (validIP findFirstIn (args(0)) match {
      case None => abort()
      case Some(address) =>
        if ((for {i <- address.split('.')} yield i.toInt).forall(_ < 256))
          address
        else
          abort()
    }).toString

    try {
      val res = queryRipe(ip)
      printf("%s - %s %s\n", res("addrDown"), res("addrUp"), res("netname"))
    } catch {
      case e: java.io.FileNotFoundException =>
        println("Something went wrong! IANA knows nothing about " + ip)
    }
  }
}

