/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2024, Regents of the University of California
 *
 * NAC library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * NAC library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of NAC library authors and contributors.
 */

#ifndef NAC_TESTS_UNIT_STATIC_DATA_HPP
#define NAC_TESTS_UNIT_STATIC_DATA_HPP

#include <ndn-cxx/encoding/block.hpp>
#include <vector>

namespace ndn::nac::tests {

struct StaticData
{
  // Regenerate with `./build/unit-tests -t @generator`

  const Block nacIdentity = "80FD080706FD02ED074808066163636573730806706F6C69637908086964656E7469747908034E414308076461746173657408034B455908086C20E1528A7E1FAD080473656C660809FD000001499D598CA0140918010219040036EE8015FD012630820122300D06092A864886F70D01010105000382010F003082010A0282010100D22558D6CE37846FC70DE4E4C19C7245166ADD41063CCDBA53F7E45F90C700DB0C84283B497902E77040817EAD45E46906F1FB94213A5D14A34F7BCFB2C6ACFCB59711042C52E41BCD9F344CAF281834599B412BBB8E5294CC118238A94E042D1F95167E8F2060F3047F834EEA32277E9B7557B874B9D864E7226EC77F3706B620506210FC9AA232C8479130D8453A4226CB4195E28939B2288455E27CA6BADA237009B02E02A55F28FD314957B89523F62B638EA9539225AF1D8719BC25703F584A189D698398E490CFC7C40FA96C5B5F5F8C0A9C4C66E17708DDEB414A3935CE6665D9AEE3AA6FDC2EE26F51F098B1DBE484F9C1D3D1996A93DA5D59397C0B020301000116681B01011C39073708066163636573730806706F6C69637908086964656E7469747908034E414308076461746173657408034B455908086C20E1528A7E1FADFD00FD26FD00FE0F313937303031303154303030303030FD00FF0F32303334313130365430353335333217FD01000216CC5A0FA69D494E6863A9713296788AE1B1ACFD37989A4395DAE45771B6553E2D788A7EB9882D634352882A2A0B7A5BA2C1A1694CA147C32F438178811F49E73F83837D1369CF3F9A2F8438E00C4EBA3AB727C02B3B1D03C67D95A4C1378D412554814F33E829F6784E8B0D02C5A18B059F274C718FBE3A6538CCCD060E6E943FDBC1FD925F4F6F6311352A425C172BD7B0F2A2D9F820D7BEBAAA0436374BE36F23811FBE0CC904C69AA952ED987CBF74D8AA0CA6AAD15E66E627F083C7B48574F6C5F05411DE85692C76D0A55086F339AA7BE188DA4CDB9DD32CE01E59EC45A9BB0509DA909C85898906386C361CA414569AD3DB8545D3B52C94C5CA6C9481FD05123082050E304006092A864886F70D01050D3033301B06092A864886F70D01050C300E04088FCAD0F240626DEB02020800301406082A864886F70D0307040802428859D6139700048204C82ACD21359F30F7E50D352BAD2A3B594633E869D1A36FD392A8F23A44DCF6EC8FC40688764D51255B2731AF3F8F151100C33D86516136E138717EC1696A671A814B1F5CD5670729647E39FACFE525CEF0F258F8B8235AD1B50484F3A0E40C2339486BAE871FBC212C274E4F0CC33DCDC1FBE2B9CBFAA8C5AA43D3DC6FD511E5AFEBF72510F19C5B71AAE4A85C3AFD0C09A85B38A3A9E82FE93F46D297BDA8DECDF23E935F93830312B856CB8548F8AB5CF3BE012E2A0477DF9C34392B32C7CD56B87E4A15C1C4FE5852DCBA2299A3225B86DD405EA7FCD523CB787468492CD0D22E2C854FEBAC8622546913FAE7DE25757512DC1CA3028C323700021F9B3A124928E1C04D2126D64BC125DF3C3B2B55952CE656D3B8DF0B1A5ECE94C8A6ADDEBE0C30D66A33CF8F959F15AB3217011B288B257FE0BF08A747D0B08507A7CE61E14721E85F73F9DD11C1B6AE3EE36B2C43A6C737CA267135E816BAC2C7AAE4DCBF119BC8A47DD2C17DB371D9366C26E11C95C3305CFF4E9D4386BA0D14789CE5DEF2C098D76F3B49B36BA43F93136F9AA3D9B7F08DBF270D3518C525BA78ADDD6B14DB0F56C7ABAC964CED5775C55A1A33A4B1856244823918301CF369718969C906AD91639EF1C5B49C2CB58F8C8C1B7FBD3552997C69FB32D19584A63710CD6D2B97EE7FD27CDE0EB74DE7DEF9C1DF022D947479ECA646406A14530CD145EDD6A1C13B1B9F12470FE90EFD8A12808357098310FB7E58E861AB97956ED825A9CCDCC5D92EB4D76C2035679306E3349B08ABC0AD809A611EB8CF6F0D888C2D24343DBB7180F2F2894E0BD92C9F575AAD470A98885595CD9C1F18FAB4411C1C5869746A10730699E669601F7D75A2B4542AE3F01055D7AB9EB7A7B8DBF1914A71FCF52A8524ACB9096A9DE896E73A8642AABBDAD3733F2D79EE60645397077944A8E78EA510D1F2C0E619725310B1D9258B56CEB61308C9A2033F872D2FD2F8C6BCDE76FCCCD51AC68E6163E68E4BFEC09CB5D47C85A914695086D52268B8B53DEF05550A2FB67BFEAD1FC04771A68FEAD6320F0944A6CB1B23126B35F9CC316D27E4EE7F8499E7898B7507B76FDD9DAF41EE753B21946EEEB5A3E82BAE96474937413E000992A1D533FA080238731667DF0811706CF958A38D1788EDA9E2D5E43CA8BE74BCE7D08ED4A4531BAA049B720AC31D7D224378A91AFAF3A8288A8B582771B3329A3DD50C8A29C9DE256B80F98FB3D2D780C5F475BA5804F18343B6E060D282B131D8B00AACA7BD8473028EB9E0287CCE265540115B446EDC3B86448C8B58920FC54ADF5D5A878B297FB1F2EB9EF02C08881F3D7D52AE1D037567B1EC629D926407488887D57EE8385D669E7784936CE03EA1CDCFE9016760B3F11515ECD10206ADC71160A8ADCACD29CCA0B1E1AA966C36BEB57F8501E60C7FC3C2C0EABD9012B086CC6A509FEF4506B16075A2A02BCECE88FD1FA9D8EE219655E625222F3C712725D087713BADC85074589F6A72ADAAB8E3B06095D77DF9F12D02F580B2695ED8833351C35A96AFFC1721DC5597E82A3B63FA112E7A85ADD2F3E2B758196F682ABC036A56F95AFF01DC254E4B3955BBC03C26866E871AEDFDDBC310E1F136D2D859EE826B8D90458FC26EEACAA775A3D28B34659DE676BB856C732B214290582D0143DC420B7D47A3938F2CD3E28D3F140A7DA8DB60EDDCF603295A73B40DD35D30924E47"_block;
  const std::vector<Block> userIdentities{
    "80FD07D106FD02B7072D0805666972737408047573657208034B455908080C87EBE6552742D6080473656C660809FD000001499D598CA0140918010219040036EE8015FD012630820122300D06092A864886F70D01010105000382010F003082010A0282010100B9FBEA51887BE59A2B94CAF83E704D943F162ADC810E51F9AF4FB273FFDB1E7826FC8AA289AD1114C136A18275DA0D428DA69B2CF4E5C5DCEAB0C3154F670A05365563F02FF9C124653FBF360825B160240D0FFC1F93B74915606E500C7B48D4D1F41950BD6125B6A12EB101968EFD1EFDD7CAE5AB6AE5DE8C33E2F91FAA5D6A35131B2F778333FC6F359D739F07787BDD74EF37268672E4CFB4FEFB4836FE91F3C3DC3F7FC67532555EBE293995D6D083542F990DE86F564A05CDC9FE576E1FBF1FCA616D2149467D1DD83A17677F5FA6AD12686ABEDD58447850D2A150A3CD9E2E2D623402E7ECFCDD6B2941666D01B65AB8C77BEF6F7026476B1FB1A2A8250203010001164D1B01011C1E071C0805666972737408047573657208034B455908080C87EBE6552742D6FD00FD26FD00FE0F313937303031303154303030303030FD00FF0F32303334313130365430353335333217FD01006CC0963399B7B3C075AB298BA6E19BCCD459039465BBDE26182C8B27EC64BD85F776159F86F7B20986A42A85B0CC590674942ED2D998DE9AEAC7728E5A05A48A1E3C749071CDEFC6D046B67C2FA0CAD1CD384DB2673AB3E6082DA31FFA5902C820C0AB67D33C4F11A33CF2E5C3D891CBD003966233F71135009D48FE7085A45BE63524F8814C3E89F9039689C9FDF0CCAB4594795BEEBAEF010BA5AB79C0EF8EB86A7C6FCFD758FE3689B11779EB7EEDD26753447F171352C7A5EBD842727AEA24471F63E10D88E4D6053928DF80FAEFB460F228BD6E08222535C18040545BA4CA2CD9F8DD951DF5562832D3B08EE380FBFBC0DC3224006971C451DF1A7BA5F581FD05123082050E304006092A864886F70D01050D3033301B06092A864886F70D01050C300E0408513C41914C11DC2202020800301406082A864886F70D030704086E9DF6EF4D3A7153048204C8FC550D6AC92DF067414B5FA6982152200C9D81E1C537CE7EA10AAC7675292F55FCDFC942EA7217D5845CCB91677470A6AF9A033BBB20058121BEC021B9128C48562903DF29B96692985CA07BE765844D54A637D2F5595EBDAC83967204879D9B35436D98C679CD93A99C17EBDBB42D4A30785A68C5D4117D522D79E92C0B514082BB3B92FF1CC4EB8832184BCBD3C95A8F794EC881FB68EA34C75D4B31D438AB8D5AA49DD47238BA8863C546CF50E2BBF8ED33C9087E06FF38804A50C6D456BA9C96A57E0F3AA359D32B93F8FA0051680FB24A09AD1B0AA9AD35883351607756C51F6BF6DA43837C135F64D370337D5902A22B645134B916CAEC351D194264ED58806CA4C941D01E34C5E5925F05BC42CB06EAA62607496F7282773AC2FF7B036461CFC362CA0C672A95907D98316A15AFE106AC0F962C1B3FEFDFFE8937A4A490445463BDF562B09F49825C96C8C745F397F346FAAEDFCFD0D9BBA38A77391C0BE2ED34EE2073941646CBAEFA327CD38667B82741B0D79986E5EF68D14A7E04D8E9675CF657F88865774874F221C4DEE21152F7BF2B0ABEF416DE93E6D7ABBB49383B3C698B4BB5F1BF779374C97F45FA4DAA59AEDE90CDDF8607D5E27AD285DE0EC0FA5FB39CC476076CFE8825DF301C77E30A0CA9A85624E78E6540979E7F450659D158EED6B132FBC4EF49377CB4E743227B60FF889D7A47031B6176ABA9E94E8C1521BE545441AD2BA295405AB118774214808A47D7636EC92C153579A0FCB7C3874B5E16E11009D8406937FE85E5EC991A2DD64D326933B44BDF72EE50A355321D63ADD1B59676C952D62F65EC9E4E9CB53A37A6B2EDCA9D93129F0D984A161C161AD973F9777442FB755F837A5D920B6D13F73F2BB1188B11FE3D8ADA61E88BC7A8E1A9A0775D38CA2CFFC1FF7C0A660DC9B982F544631472A8BBE94C7E0EE60FBCD33F3AF0395438A784C2CB09AA2D9174DF3D18D906BD719C5D4A00131836AFF2281E88B3931E25B43C72ABB6E45BB428EB2824F1B9572E6232F078B262CA91017068DBA14E38CEE23F3C7EC23B5B30005AA7D6AB6FEA6B4A3BD84C184B7D7FC089465543ED80C3E8325C6F4FC104B45129CD4E4048D4BDB2CCC72F47695E8D8E04ABD9F8B9019BC3AA5765B5E831231BB1FDB6B610839BF94A31BA9AA49FDD2DDFF9F7954EC330A459B7D98726AECF649694446EE56374CD3A0F8B7655DE2F246465CBC2C5B9C32A0C0B3317BFA87676C9140B346E6733BDEB8D65546695E8B63BD713C13000A52505253498BEDC04C22DF23514EFFBDCEA5ACDFCCBAC600E6B60F84C794E391D59C2B460F14D9C9D1B66341C1C7DEAEBF3F576B4B80ABB30A5119EF4040369D238262013B78B2E09A72EA5600A8E027575AA6EBE51F250348168DEFC5629E30910DBDD3F7C5C004F976ABB0AF4523B0F5761F5752DE3A59ADA3949EC2C0D45486EC1E7E636C06AA616AE2E7D112A4502DA0D44A6996E6646A3D70EE7C214981724A950528C71E7FBA1783A4FAEE60FF0A55C008CB9A7CEA2A3FEEB47EC349EF34A7F9FF8D9F4A3E76E726FEE043DAA20374836115FA8D98ABCF96ED6D547EDDE141FB49998D233196B2A3776BA718F0D2F996E04B400C493D007A29920214050997A1A6BD1ED19734BB7F67428D4DF15EDF3F4892900AAACA87D40C893BCFB1BE5F778D85E8E95B580233FB1241801D5F678ACB70E4D40A8BD31A119"_block,
    "80FD07D306FD02B9072E08067365636F6E6408047573657208034B4559080867054FBF16690686080473656C660809FD000001499D598CA0140918010219040036EE8015FD012630820122300D06092A864886F70D01010105000382010F003082010A0282010100CD511309A4B59EE36228149E496B8C8D4CAEDE714CC8085A43DD6F69482D13FFBC79782EF6AFF443F57E9C1A5CE8B36551AE006CA8B97AFC62175974EAD15693E11AA9B4B86AB80370123070F833F0FC1847FB15B7608B653585206F0D50D656445B2B0ABA28E6AEF8BEAD3FECB7E15BAB2A31B74C477341486CD78981258C3A53070A4E5A26000428822AB00547F0C2F5532D1EB232623CAE1BE0A8DAF840D304CD2A8C5FE666077ABB61DF2A1D2E1445581FD450A295C4D6C9101C8B3BCBAB6709114F087B9C2AE1B2BB90984696B7B7C18F805B504C24C0C13D8E8FD02BAF0E647502C6D7812008BF2FFADC99FBFF2ADBA0BD9C23938A46744659FE271F1F0203010001164E1B01011C1F071D08067365636F6E6408047573657208034B4559080867054FBF16690686FD00FD26FD00FE0F313937303031303154303030303030FD00FF0F32303334313130365430353335333217FD01000A33AB14E9F16573E9491C4D764B3604309A47579AC05D54F7EA20AC5EB3B2EDC5C7BB90FED466034C7C8EACF6538A64394F7823CC35B5CDB07ECAA20B2062AC9C0FC88B0FB2E432F1F765E3EEB8EAB6641DBE7BEAE216C6F915BA18D4385797CE5642315328742DB29271E2517842D8DE0F7130F01C22B4A5D70041696FA369EDE874DCB7CAE4DE9A0594CB8BEA81C8C1D3FC504B548AA62ACD35C347C87E28631CB217CBD481796C3B911B8C7D8DABE80086F38E29C7108ADA6BA3E54CD8B3504BE44A80F55D47FF04B23A993A21378F99079420780DBCF56DCC6D4375EE6D15D3C837A284B31FE4D686599AC6B6C1547D980BDAEB4BF00BDF40708347D59681FD05123082050E304006092A864886F70D01050D3033301B06092A864886F70D01050C300E04088D431092DD89113F02020800301406082A864886F70D03070408890E15B8027D80C6048204C8E83108D77FC81AFB28044121620F0EC4474C588EDAC252698F5D62D97CBC3EB7FC410103D249744A26D631A6465F708AB691F217462852964D122B7B6A06EE958A028DF950338DE90AD60FA55EA9B6545FFE06B935F0015BB20CF71EAC495177A41590FD25E6B7139C7433A23422BC220D3A05B4ADBD63123A6F49178D211B6CD4D86E61D779341ED2DB23F20499F49398C7EDB73FFCC31A6AE9F6815800473183248055A470D7178FDB2F1418805FB7D19537238FFF02141739BE8CA8C5F72FD0E78065711A9D1F214E0FDD516058D605CC47850921CD86808E4B2A143884BD94795C4CF3515E15A2D1AB51BA0188BCF4E899A48017991D0FB856C38214D308959462BE5E8BF671B020776E93730900EDA486A365B5BE96ED4BBE7972EB4E45EF8A5B1491AB74B99A174B2F1B2EAABC0F3A511C086126FCEDB723B460813CA4709BC6324925DA3AE793B569407F7566A81EE5E463501830C5CB98A711664CB549D44A4CFE960AE808B45DD152A1614B8CAC06823F8BFE322B31487ACD365499974223E1D3380B4B49D32E78C3180F35CBEE561482A674D8402D8186FBD4AE321EB7762B04D78FD31CC727349E4D33F425F2259A667D89F5918AE0FDAFB536A349724A4A55B3595D3E18D619A627A4D046711A05302C871D3C95C401E5383D2E0852DF3F925C449E43D7B7651E976F6C6A1DEDD975D555A4374C8977C05B233CF8F06FB52434F385615B3B05DE9A384CCD15D6CFABC2FBAE6917D2F6A60E53235BFDB21ED02BDD25829316D1795ACDDD82C99352678BBD2C467EF36541AFC846B64E2C5A2A6C67AEE531D554662FC0B539A3A40BDDACA32B79562FA657E0692535BA85190F268A8189A078AE41CA79EB9F4CD3A17201B1059D602F415D8626AABBCBCBA2FBB405B51887E48BD4DF2DA2AFB9740A9B775185FFEE8B6F7CF99F43175FB226181CC171BACF5F6A4FA5D9CE3E35528EFAF805CA878EE510FF361CAB54DCA872921D03B558B3BA188E5F78FB5058CBD1DDAA783A3BD10E891739FC3CEBBEEA5E49199325742AE8E9CD1ADCD80D34DD534ABDABD271827689C96DEA6AE675A322874FA830806388D7C423E0A81B41418951ED86D042B99193C7F0614DD0D90A052B0BB956A7376534E18B2EB1FA23ADB55096173FD68352693952178CA88B3F55449EADA6D2D44A3694C75040B0C0A6EEA708130673250AE3868F95DAA49FB5F487BA940F042F453D897D607ADFCC454A2C2AC85912B0B19E226F35A22344BE516ACA9FCB9895ED6A550AD61CF438A2F14A6C5F16F35E88B840C73039DCFF16E1041F492C67FC0023FF761DC65B8FA9821DA16DBEA709CA09D70BE4CC3D5D2719550638CF5F622692217F12452470AC24F1F0C35C5686264A308E613BD646180FF2301946C56A43F5E47B30BED67623CFDA9A7B8D71D3BD5C42539901C79C1BE573BABDD8452ACC1D7CFA7E10F6CB8F5B8F2EB87652223FF672AF37474089CC9A62761C2BF6DB1D6BEACE4731DE3A804CBD621ED673F4736E8F7625E7D614CA0F05F6E48D31FD058ABDE81A11C08D6B65B7965686B54249765539F892D7AB8E04BB32F775D6DFF9438EE2942A772A2C37CA656C45A020E9482EBB25173342AD48C68A6C49ADACD0727A57613DBF891A230C5EE2F252417B7CA6A1B1EB444BF3F21927683017433C2EFA2747C99AE26D1DC264E99D509971E59E98F5BB5B74AEE2C793B9C6"_block,
  };
  const std::vector<Block> managerPackets{
    "06FD0A01076108066163636573730806706F6C69637908086964656E7469747908034E414308076461746173657408034B444B08086C20E1528A7E1FAD080C454E435259505445442D42590805666972737408047573657208034B455908080C87EBE6552742D6140619040036EE8015FD091782FD091384FD080B80FD080706FD02ED074808066163636573730806706F6C69637908086964656E7469747908034E414308076461746173657408034B455908086C20E1528A7E1FAD080473656C660809FD000001499D598CA0140918010219040036EE8015FD012630820122300D06092A864886F70D01010105000382010F003082010A0282010100D22558D6CE37846FC70DE4E4C19C7245166ADD41063CCDBA53F7E45F90C700DB0C84283B497902E77040817EAD45E46906F1FB94213A5D14A34F7BCFB2C6ACFCB59711042C52E41BCD9F344CAF281834599B412BBB8E5294CC118238A94E042D1F95167E8F2060F3047F834EEA32277E9B7557B874B9D864E7226EC77F3706B620506210FC9AA232C8479130D8453A4226CB4195E28939B2288455E27CA6BADA237009B02E02A55F28FD314957B89523F62B638EA9539225AF1D8719BC25703F584A189D698398E490CFC7C40FA96C5B5F5F8C0A9C4C66E17708DDEB414A3935CE6665D9AEE3AA6FDC2EE26F51F098B1DBE484F9C1D3D1996A93DA5D59397C0B020301000116681B01011C39073708066163636573730806706F6C69637908086964656E7469747908034E414308076461746173657408034B455908086C20E1528A7E1FADFD00FD26FD00FE0F313937303031303154303030303030FD00FF0F32303334313130365430353335333217FD01000216CC5A0FA69D494E6863A9713296788AE1B1ACFD37989A4395DAE45771B6553E2D788A7EB9882D634352882A2A0B7A5BA2C1A1694CA147C32F438178811F49E73F83837D1369CF3F9A2F8438E00C4EBA3AB727C02B3B1D03C67D95A4C1378D412554814F33E829F6784E8B0D02C5A18B059F274C718FBE3A6538CCCD060E6E943FDBC1FD925F4F6F6311352A425C172BD7B0F2A2D9F820D7BEBAAA0436374BE36F23811FBE0CC904C69AA952ED987CBF74D8AA0CA6AAD15E66E627F083C7B48574F6C5F05411DE85692C76D0A55086F339AA7BE188DA4CDB9DD32CE01E59EC45A9BB0509DA909C85898906386C361CA414569AD3DB8545D3B52C94C5CA6C9481FD05123082050E304006092A864886F70D01050D3033301B06092A864886F70D01050C300E0408BE9C46B0346099FC02020800301406082A864886F70D030704087D54670BC45D4783048204C88743710513982AE19FA256A9183ED15DE292934CA6B222D23BF9F93CAD9F06041F60552E72DF8E998D5CC47B0F04411E6A10809C051EEC3204B0221A38D1C2E66F7B8228F132A3FB5E2E4E7BAEC449A383A3208141D85EAA226DA932EA6A56C6F7878ECF32F31450A8C597D5A3506D53E360F0ABF0EE1421AB55700983E39F482E09F894FF8BD14EBE00700E323018CE6EEE8966C853B8AF1F955630752305422687AC4DDF01AFAE374D2D5E6138B729F9084001C6CBF9867C9AA4E37ADF9E848F555011978C8382C30D888BE6F49F97539710B68387843E504C8E97033703C64918BD0798714985EA335BE3B584A9B5DCDB8D881B968CE8BACC243C929EDCFD801031542B3D49544B2C3BC77044F2AA33783301BBD9B1CFD7AABDF8842A1FECD0C816DED4CFE22EEE5BB5BB141D84E0C1CDB4B5ABB5A48EF82F803DB484644F99E1EDCC0921CA022C4254386AB0BEA18DB6D28786B78BB22F50F5B1149D1975257591886138FBB46829D9E7A986F2D5BFFCF3B82F9E3F7DAA6DDCC0693E4CD56DE5072963E28604EBC02911A9C5616E0C8C978308746A08DCFFEA349B61D500B94384380D65E2EB583CEC6C628DCD80E69B91156AB494C2D3F0CB07F308CEA541E377F5A0233DCE327892AE869BE77E4A01433141C45FB9CD3E066BC270C79B1EB660ABA383898BC0A2E0423E6ECD1E97CC60C474CDB184711480390395A5BED6879828D8FD9C29451C9317D572366E96F177F9057D3312B9EA6E0B8F9BCAC45BE8F34DDB795FC5B18278704CF5C8E7F7CCA74DF8FD37483737F4F9E7ABB131147D794BBD2019C5BFE6B38D1561A3D04DFE98ACB9F8644F688549F1A3F1E8864E094DA6653B52BED4ED897DA98F5C54682A8B0CCBE8350A2E66B0A958D6BB77B4157746F039AEF8056FAFAB8CD435F0C7BFE5DEE332E49BB48B6A0D56DA9A43AFAE01816EDAA8237997B1DF55733FDEBF35D95A96ABF86AEB6A959F0029F21B59E2C345E4A9274E658EFA7CF7C8C4E413AEEDA84DB16B32421FC44A7AB3F1F93899A8F27BED9B0DAD2F802BF4C5321B8F4845F04EA67E2C1C8FB4DBC3D147A8A6CA8E782D20B88F1C7A1E642DFFBC83F9A3B40177478F5B2D455144C003C78DD7CDE8187BE975E91ACB7FACAD457EB6B2F1C0750457047A6E284B4DDDA28D3422B99360162BB0D1D31202E3FAE5E1C1E768D2775CDC8A37E6BCA4359C3F275388D01AE4426F27AA3C1DA7967A69E3390EA13FC2350641B7C9AF3E4B1563D3009FE9CA72C208FF330A0FF3D159410C647DCDA1340F20957119076A38160337DF9ADC31C74FC58589968DDEC409EEE43EA91B8B857C2CD96FABE560065E3B28D9DE12E2C6F283AD7C071AD366C7396CE1ABA5783C6B0F1F4B5D73F9AB345CAFE57F2C690BDDF09F1ABE2F20DBC0A26DC0F89AB48F3482C877E14154CB87025C8BFD45CD506F4077681813C07619FB65CE814978C442F11810DC79E1038DB1E326CD2EC41EB509034F096F89E2B14FA7ACDCE90777013ABAD96AD3E8EE26700CB785EE58A5FF71CB7730BB6AF0479B742A60492C307CAA7422F3761E2EDF043B267EE2C8631C53754B6E478323E9871E62824A5A7C4C4E338FAC170762EDFADF264A70888C176E681F19CB0B0263497528F5CD051B74DBEF9A3FD8FFAA0B47E9DAE2A76ED69F412D805347B2C438FF3FA9E6059B8AFC16102AD7C407459697F99E7F82FB36F6907A5D86FD0100793E1AA0BB0E32493E48832DF518EC628963AEF0A940D22DEDAFB1715A2E663812E13FDFBAE6A973820E1E12227BF02B98C3DEF232A41FDAD8E1941475C3629A35B2FA3AFE2B39AC11FD1DDC632C1F83B97261E175060BF76DFF9501579EE1B48D1507F12E62F1C941A0AD95BB955F6CEDAF168230E2AAE1B4F3B040EFA3C12D6182F82BC85906475B5AE9366BD39E75A14742C3F4EFCDB7CFB407BEF02C6869F7BA1E25CAF1BEE1C18339ACD072E6631511B856760AFC2223D23A24CE29B197DEDC3C3E0FB6703F6A819BF42297851E1926395C2E2F104FA53E0F574D5CC59A38A9C6B85BA7BC3FEA4A37C8DFCE3155B4506A476B4A757D5E5C3B41297B299A16301B01031C2B072908066163636573730806706F6C69637908086964656E7469747908034B455908087A99F0E6EB3E06D31747304502210094B2CB6FBD9020A52E63810013C4A04DA384D9469693666D47F940B36E8558BC0220610D631462EF94A8B0E4FCD632D8A0D1452CD7428DD518F9CF965E37ACD24BAD"_block,
    "06FD0A03076208066163636573730806706F6C69637908086964656E7469747908034E414308076461746173657408034B444B08086C20E1528A7E1FAD080C454E435259505445442D425908067365636F6E6408047573657208034B4559080867054FBF16690686140619040036EE8015FD091782FD091384FD080B80FD080706FD02ED074808066163636573730806706F6C69637908086964656E7469747908034E414308076461746173657408034B455908086C20E1528A7E1FAD080473656C660809FD000001499D598CA0140918010219040036EE8015FD012630820122300D06092A864886F70D01010105000382010F003082010A0282010100D22558D6CE37846FC70DE4E4C19C7245166ADD41063CCDBA53F7E45F90C700DB0C84283B497902E77040817EAD45E46906F1FB94213A5D14A34F7BCFB2C6ACFCB59711042C52E41BCD9F344CAF281834599B412BBB8E5294CC118238A94E042D1F95167E8F2060F3047F834EEA32277E9B7557B874B9D864E7226EC77F3706B620506210FC9AA232C8479130D8453A4226CB4195E28939B2288455E27CA6BADA237009B02E02A55F28FD314957B89523F62B638EA9539225AF1D8719BC25703F584A189D698398E490CFC7C40FA96C5B5F5F8C0A9C4C66E17708DDEB414A3935CE6665D9AEE3AA6FDC2EE26F51F098B1DBE484F9C1D3D1996A93DA5D59397C0B020301000116681B01011C39073708066163636573730806706F6C69637908086964656E7469747908034E414308076461746173657408034B455908086C20E1528A7E1FADFD00FD26FD00FE0F313937303031303154303030303030FD00FF0F32303334313130365430353335333217FD01000216CC5A0FA69D494E6863A9713296788AE1B1ACFD37989A4395DAE45771B6553E2D788A7EB9882D634352882A2A0B7A5BA2C1A1694CA147C32F438178811F49E73F83837D1369CF3F9A2F8438E00C4EBA3AB727C02B3B1D03C67D95A4C1378D412554814F33E829F6784E8B0D02C5A18B059F274C718FBE3A6538CCCD060E6E943FDBC1FD925F4F6F6311352A425C172BD7B0F2A2D9F820D7BEBAAA0436374BE36F23811FBE0CC904C69AA952ED987CBF74D8AA0CA6AAD15E66E627F083C7B48574F6C5F05411DE85692C76D0A55086F339AA7BE188DA4CDB9DD32CE01E59EC45A9BB0509DA909C85898906386C361CA414569AD3DB8545D3B52C94C5CA6C9481FD05123082050E304006092A864886F70D01050D3033301B06092A864886F70D01050C300E0408D2903CA7754B797C02020800301406082A864886F70D03070408BCF9AA6117C4FD68048204C8B1907E5F49F027B46BE32C87BDAA1F3767E1E67D5A68FD9F18B4EC9258CBC52A96A4373B031F6FD0D37EDDDEFDC5ACF229EC6E3AB270721864C36854B3E86410F7E824A95934A9A4110A20970C447E81B29A9EC30D4A79E25B6893A7F03755CB5A2ACBE8B87358B9450912E258AD97405587E73A0B74027DFD12958647DDB5CAFEA76A63A233F301CDDED0D0C66CCFE67CC2BB46141B6C04159F06158E1EB75E2FBA186FF2DCC8953745E3DBD19C128A3F16D3315587907D8D818D5A280C4BAE35C3B2A97DABB32471AFEAD15BEF7C489BAA5FFE7BFEA8F2F18F04C1EB0451A8D4085B133A966FFC1BB62B9FA2C9B7D7A6E9765DCEE372E552CE78637EC5965D2196A2B4746BF6458B660707EFFCA654E103C1D95E561B833813BB6BAEF0A04A0436B12D27E2F5B2BB208644DB9F2DAE85D2D60EE4B2CCAE1DF887564D946E502A3D4BFF866A1AFF580024CD9488D628134F034E98B2590081549C49191D157C50AFB011BA26BA4531DF5FDDED55FEC9F6C773A333634E63D97A245CBBB21FF9D23A80B8258FDAC6AC9164C4C9634277459C319713D421C3413C8A81D5C1345D8769BDC00D691D9B2E0D51264EAF08D1FB2D673C9A742401F4B873F1C2A46C9192D83DE892804C7F0359CB4A0A1CA1A300976A38D484EDBF25FAA890473759F92AF695ADF40C3B70A43CA1560FC94DE23005B8B03A265E0A0EA1BEEE8E74AC1998477A060A6F9239DBC0C037A7BA8ABC53D2EC9C292F6E644B60ABB25458A0BB0BEA88A1A53CF4FEE21239EF876CA03B976ACD644549CF0F8FC1FEB7F6FE85770AF93A991A5D3E67141B8BE8EF5D430ED0A6F498118ECFA69C5304EF76EA9E3B7AB69220F0B3263A3F961785C8AA76A7AFC7555A58AFF69CAF43251026DF85AFE5076DC83442F92460980A234320B44614ACD78DDDB0DE631D5DED0FBA6FFE2BC9EB30F07A5C652969CE479621F6F5AEBB70EF3469282D90A8A13604C92E56FA2F97A22B58F637AB6A15168B277F07694463B8479D19E01FD0CAFD396C849A6AE96211E8FBD50EB1A1561E406D6E6E7C2D7DD4886E368996D09AEADC4F96730A8FC95199F72C2875776430F595BE0B4DBC91975B76282684C245F4F5F255323BE7FAA3C4D0FF9DE6842E67A1B60999CDE11F54921E0A8D375B83F6FEB95DDE1D451B43FBD26BFF835AEA406D6D941D4D4DF3F4CC40ED319365704AF6EC522FA6430BC949BF1F31369BECE307D23B487BB57F6E91337A555BA557D74C53E0AF245BDABF4865DA872FCF4BCD010C68AA3917519F96545299AB4AF2ECF47E37FE07CC0B01FA695F63F73488A3A616225666E7508F7EAC915F10FA5BC55C72F245B605780B5823C59E1F7FE4C8FFD402366E4C046051F4B39700BB8CF9AA32B6DD56B03FB5FDA2FA6BA93D66988962452FB0B53FBA75BE7B00600EC65F5AB676CB6C639A822C7BC570E12E02A23AB9074242B5BC1364E8AF87D7824CD729038B10054DE8B81588DED6A890EBE62F32C56177518CB4531DBA009698E290EA940848716DFFC313D7A6F574C3B57A3EFCBB58C3DC9F11068CA27FFE27F4C5646948043D4274713425B973CE8B617368D1B5D998399E65F95A6FC6FABF700F37244EB9D09067744B97533225BCDD671C9F442191B0403F7F5867DCBAB78ED268225C30A1211B3631AC39A9780D7AAB96C9FEEB094EAED9B0EC8BBD10AB740A786CBDD8E02CD56833CC599DAE86FD0100106508260604E545E4EC827E6A9AB8925839789F0FFCAE370F090C156036D81E796CC840F29CDD672BC644E82603F4320A5A958FFFE1E023B9FA35E05E7D4585255E42FEBCD3346AAE3ED2D0927A7B72F5BE709E51BF2D52BB04F10C27EDEE5DF0C66A6C2010352D7BB251FB6AA86865362643641241710E04B9E668E0910BACB64338A2CDCCC799028D460EC826BD7E623CAB587A90F1248BA8C18BE647942CF0A5C1D28FFD7DAB5D3B3D1D0C775DCD83278F9053DD97AF86E4E9F1E3F9051FB12126974AE392CDACAFDA600E0E69E3D61322349D86EDF81B8F057A3ADF44F4E91AF491EFF8E7AF030F012FCA0ECEA8B1C303B98B3A0F9C49D269DCDA98A8E516301B01031C2B072908066163636573730806706F6C69637908086964656E7469747908034B455908087A99F0E6EB3E06D317483046022100FAA0849B9071E2836F81A8744E961B714CEB993A1890EB0F2383BD12EE441172022100A63DE0175D2211CF2BCD97FF8E3237D434166C832333D40FBEAE3156B727CB2E"_block,
    "06FD01EA073708066163636573730806706F6C69637908086964656E7469747908034E414308076461746173657408034B454B08086C20E1528A7E1FAD140918010219040036EE8015FD012630820122300D06092A864886F70D01010105000382010F003082010A0282010100D22558D6CE37846FC70DE4E4C19C7245166ADD41063CCDBA53F7E45F90C700DB0C84283B497902E77040817EAD45E46906F1FB94213A5D14A34F7BCFB2C6ACFCB59711042C52E41BCD9F344CAF281834599B412BBB8E5294CC118238A94E042D1F95167E8F2060F3047F834EEA32277E9B7557B874B9D864E7226EC77F3706B620506210FC9AA232C8479130D8453A4226CB4195E28939B2288455E27CA6BADA237009B02E02A55F28FD314957B89523F62B638EA9539225AF1D8719BC25703F584A189D698398E490CFC7C40FA96C5B5F5F8C0A9C4C66E17708DDEB414A3935CE6665D9AEE3AA6FDC2EE26F51F098B1DBE484F9C1D3D1996A93DA5D59397C0B020301000116301B01031C2B072908066163636573730806706F6C69637908086964656E7469747908034B455908087A99F0E6EB3E06D317483046022100F3696E0FD213A890A89C22282EDF44EDFB59944A3F53479F669D38FD522F99DE022100E35D8116810EFC9D26AEE9B8A88ABA4CBB713B1AAB19174C53E8F532949C04BA"_block,
  };
  const std::vector<Block> encryptedBlobs{
    "8247 841048E10F2E5B32E25F82313FA65F2E83D7 8510DC331EF7FA210457DA66E482BFE1E7E1 07210804736F6D650802636B08067072656669780802434B0809FD000001499D598CAA"_block,
    "8247 8410C1DAA5E46775AB37520D86B6FEBD7A1D 8510A90A73A1D30F17F847A267710277D040 07210804736F6D650802636B08067072656669780802434B0809FD000001499D598CB4"_block,
    "8247 8410C191BA54FA84F03CAB68C57455D388AE 85106C052A756686E78D8E3D79B543A84CE8 07210804736F6D650802636B08067072656669780802434B0809FD000001499D598CBE"_block,
  };
  const std::vector<Block> encryptorPackets{
    "06FD01A307660804736F6D650802636B08067072656669780802434B0809FD000001499D598CAA080C454E435259505445442D425908066163636573730806706F6C69637908086964656E7469747908034E414308076461746173657408034B454B08086C20E1528A7E1FAD140619040036EE8015FD010882FD010484FD01004AE635B3A8E82DED40486A50BEF392D5F6605C0F1C3B0A7B7B5413F1AF117BE25A24ECC4D9FA67252C03B12919F1C39F2BD00C93CA8D8D5D3A31C32D9233473E027F353837D5588178D94175BB0C09E165DD9017D916EC579B880DA3B0C6785151AA2F041E081E95B1241B485DA27D4E9E817B372833E29C54CB021DBC161E9483857DD9388E940007F5BF7E58AD64655165ECE1995BF580353416318F8D6A7246602D950EE6ACABAE9D6CFA5B9F628D729429828BA8B899499AA04CD1C873286C98CE7386CC0186859E605610B6600F96C4818DBC3894DB346EE5F34C294CA1A51355D5DCD9A7BC78C996BC9B16CE760283C839A84A547430CF601B72023FE916031B010017203EC5FDB3968A84E29957486CF17D3323B03ACD7183FA0A3129795F7A593809E5"_block,
    "06FD01A307660804736F6D650802636B08067072656669780802434B0809FD000001499D598CB4080C454E435259505445442D425908066163636573730806706F6C69637908086964656E7469747908034E414308076461746173657408034B454B08086C20E1528A7E1FAD140619040036EE8015FD010882FD010484FD01002F272964A406B376CD77D95274BC8F1AD52BF6658422557DBF1550B8254D596AFC271C61205D0A135B79B0AFABBE591DFA810A9CBD91A472898AE2255BC71B1F90B6B83FAFEEC0432C06904CBCA5FBB8FBDF20619CE03AAD66B9A0CF40A288098F624E7D82FCF8768379B6F3395BAF7DDBA6C2E9C0C59A522FB301BEEA3818F25639A4D39312D2350EB5B42FC7250A912D409A7EFE68D94B4E86EADAD98D43945FA80727134E6C640E550004F7BF43189A2631F1423F49F5300EA0F48B21EF72DFDAC9D30585A2E9A8BC04A2538300A210DAAECA62133BB14D55E0EBD074D41CDFB7CD2C7192AB71A2532E5CF582F874AFCE232562689FFE57F7A30E700E49C616031B010017201CB5DF425547F997625C07830BF11BBB18A3150E4D3DE0A922BF046D4D27E012"_block,
    "06FD01A307660804736F6D650802636B08067072656669780802434B0809FD000001499D598CBE080C454E435259505445442D425908066163636573730806706F6C69637908086964656E7469747908034E414308076461746173657408034B454B08086C20E1528A7E1FAD140619040036EE8015FD010882FD010484FD010026C5396EA96CC7E0D84306D284B94ED4649F7C1FD86D2AD91424BD333DCF1D705EA3BA149557EFA4B9DD8EB023244DA41384C5CCD880A86F0AFA2FB2AC326BF6CDAE20EBE4D6DEE819BF2617A8522583FD5316A11DEBB4F909FE5CA0DBDDE6ADF8FC0A2E488679336A2CD65A2BB28F5A61F8964838F21FE405DDBE4E0E0F6C3AD095614C1BFE47802DA5667DCC741C1614184794D55907B03A68ACCF425A36D2737D1D65C8D82FA8CF5DE6156FF01CC8AC963EA8A95BCB07E64E72FB0EA3655F2F1F6770451DD1B10C51D32C39CD40D68438783B1E9680BE36A139A372001826876AC78AD520A2EB26679048FF03B3BE785CCB6DED0727C5BFE2CBB01BB7616016031B010017205838933A7C7969C5B0A572B72FF94AB0E6D9155AA06F803BCF9AECF06C69D466"_block,
    "06FD01A307660804736F6D650802636B08067072656669780802434B0809FD000001499D598CC8080C454E435259505445442D425908066163636573730806706F6C69637908086964656E7469747908034E414308076461746173657408034B454B08086C20E1528A7E1FAD140619040036EE8015FD010882FD010484FD01001599879738B8366C51F18722DEE5A8807B4AAD123068B7F1E9656DF70FC8C41349E850FE966C707EFE6FE42094B1AED4E8AD775FF572DD98F82D3F017BB6283643B8354418F3849752D6D1330353B8E2ADE169A8DC7BEA4AF851979CBA4F403B2458DDA332FC02F7C2E11A4D794AD97BB246226C215D8B2B6A90C927006293375B942E725693CA5D8F86BF2EC33D1B2CE44CB11BB401999B96ED28A4EBAAAFB02279357C50AD9A8787C15FE8368F2ED9E6CB81B6B154371B777C3CB0FE658C77BFCD13742FF63F5718531C586C7036F7A2AED4599450FD655A285F3DBAB2667773745E854F267DCB85B6B6A9F2F90CBE9CF28451ACA7E52A9E3FC28D5B6FFFAF16031B01001720EC32FE51BDC44292452B74A6C74EB6DA197CBD0764156BABDD2A3CAC9C601D00"_block,
  };
};

} // namespace ndn::nac::tests

#endif // NAC_TESTS_UNIT_STATIC_DATA_HPP
