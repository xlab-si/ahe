package maabe_key_authority

import (
	"encoding/json"
	"fmt"
	"github.com/fentec-project/gofe/abe"
	"github.com/xlab-si/ahe/ahe-key-server/signature"
	"github.com/xlab-si/ahe/ahe-library/cgo/maabe"
	"io"
	"net/http"
	"os"
	"strconv"
)

// TODO: communication needs to be secured
var auth *abe.MAABEAuth

// todo change in dataset
var VerificationKeysDataset = make(map[string]string)

var auth1Param = []string{"auth1", "65000549695646603732796438742359905742570406053903786389881062969044166799969", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGPtQHjSqOH+apv7LhhhNwh7luI0SC1tZ4YXKxsXgiWZQ==", "AS7MpEb/bz1NA8dum1x1Lyi8N7NkywWsSjfrMuHDJFlwjyU4b3LJRiuBWX1lriCSxLl3khVdzarTK4pt1BeSU0wtsQ71IzsP45Yrnuaku8K1veAaVPNRPULfly4SjzG/EidOV0foyvrMNxbMhpnbebIvDk/zwj6Jj2lEIKO+MIel", "Ltzr5bSo0lY4xO2nLlF1Rzn9KFMQLxvUc6hNVzn4upJf5qyNFlXGOcQCYmAJmVyDKYxJXXvm6KXlMg9CFjc6iA5p/LgYJAIx764tNRH9fkDZNCXqmm+/Xq2Hz6zP+RJybLPHTV7aQrGgMjrRNHdsPkyTLJFbHiBzIYR4cy/ej54uHdzewL+zYYEMO/eFX4zED291gqduyoo6y+Vw/7h0h3h25PCNm3+6wgUZ1zx9bWyZX0mxGVoleaiOC0shgIplVvU6o4SqXvHP2pcoS82BnNumDvbdWFpgV0yw5z5A/IZ1Yia6uuz9clABpO7FWUSKEHTaOKuJxykMAYgcoBlC60PyTA6892h9NU0v/SepFOd7pZ06nj+a++OZEhTke6W7Hfsl5+pCFK9WAbCnmJFt/M+YkFpkQi3xAhapOs9izz1+MlwBVaMZ2Km36Ctt512nGpDwzEcdVmeTDI88Ox2/Q4S6Fg/VwO/PAZqzzYugE9rTGedosSicQNLC4YyFHhTr", "auth1:attester", "fzjtMDP6CcU6T7f3kEKUT5peJxNzjKR3JvNKWXKA05lWoBufm7qwU8lq+wKZKLaxDenUqoPquNfjawxLCci/9xti8EigSCT8Jc/KG2wE8y+GTiszg2wHwLEN/fMvrmD8MBiuRa8wXmjRJ62/pXXKUVhKdzvu6g/fDAqaquygk+Q8cZMUAz83cJ6FtjYvpxKrwjtTSzz91Ln3GRWFZqcv3IZq+4BLPFoRMsi19vRoPw2zRGJ9sFL1ZCCfg+CdrRJlZKM96PgvxFlnmeDU2371qm4z03Rr8ftRCDpBe8dUyA4PC47lIb7ryiNU7MYNYlDFhQW+oudybwz8CAuLyBqjZDpvodqjodwdtKCq/a0x7V+m+yyvMjDnKUFP7fWV1p1Bc3IyR5NCC9fBeOD8xRJCOqMunv6tFJE6exfu5nQ08Ww+QUhXz72ht/xV4gEQsQBhsW7tCw26pBEEfIZWWXMdU4gw2Lv9xvxPd5O/k71MKRepFQDpLYwIApENF39mj5ZC", "AUryqjUxZQhTX2LxpXgmxelsJidz2Cug6stiEviOFbTZOIf2dhhsP66iLvOscJ9DSj061E+B/fCa2ncBK6p2tr9B6FW3z/AZ9mk5+do9OOfS+aJAdKQNmoUkc5T8Sgt6/CfisRygoWl4nPvUyWfgUTDEQwiHSuh3bFD8KXvcdHaO", "29118608764048260068217396754931132629645991733540219786873562777196875679894", "59330989450422704035688610596065865010996718686086346624176288016886121725566", "auth1:admin", "FcUQlcmS8QvQtG4co6erYhRoooOihi3eVVkmdW7TJIc/j9zh9GenY2QNEnIFwuYRog23CdGPL8GCgr8KHS8J9W0r9HL+7cYfM+NJ2txSy5iXXNFYu8+ShYMIIwZFMsmVJx11RpKvUb2T2SWwI5TPus0Kc3ZOCI2XXqyTwQY1lLFXHre9hlGl8MsE+LVYMO45DcPOyGHy0O/ibKyONv2prAe1P/3AzapI6roVCaEHoU15UfL874sw0cxZb9TBnwbnd0QBj1akPNQWbGjGyMU9tKE4cXmb/MJbIr4eoa38f9oYg4SsA4ylFsf11OiSV0ZS5MKdydFO/lgrgOvwv4LY6Te1lAovmQAUciZsNPlQdul5dujbVCzzCxPAc57d0LdTDZIUEONITkCRaIYMwBFV2bGCk+lWq4OdO3p9BUYUitkQugs//r8yEDUKdS8uO3JPX2D3CTrmbQseboqJCOv+a40sOzbKlKR/7TipYKpI1uoN2VC0FFkqiLywqxhlRJSW", "ARj1YkuCk+JaPjBR4cJmcXak5VqnLM0wvaYkeZwx01hcPxQWikTISAbeRT6tcRK+//2n6kz+Rmz6C6MzRAjnEH47VSywrMyWS4SY5q3DjgToFeBwCvWZEdksMmHERwcT2QOc3RnfeLUuTrcjYjbeShygpxFxkJuHX9ly4/7IOEj6", "51424932432807832699107196118298849254124435558757919666328092656044115761611", "41677437580994374905021816141496362513306552530749182432451874517053955164779", "auth1:recovery", "DHzOWPeVCBBvhzh4dgoLH7odibkNEjhorRS5k2pSe/ZyIEXAggR6tWnSnmbEn+BaBueLyA3wVzsJp6WvGTdlTVz5QqTp0Uxnu8ueXJtmbmYoMSe1g3ABxQkXE11RIGwvgraVB+73cdXCpv7AWZCaw16GWDewLaBQcS+Lfl98uoAx20shsUnMWOk4hu2v+ARjZO5GsTUu29HF+E5TNaaFOUB56SlcADYB64RzswMqMSnfMjeTAJMP4G4R4SQFkj4qWKLROYee65oKyFagkHaCR9iSz8uvGCJkTffGmJ/hbb1leXaC8zkL0FIEGmhikjQ/3B6Hzp1+wfqd0LGlaBllkjaiz3zhgYrbSfH7YSYYuDEP+Bf0CBXkLm64rDhBGc7QVRUKDKQkFXPn38HII/eXlpAFMQRlmTDsTeIM3J0HCBJekLfwpk0IrHzOxzoQtOkEh1R9vqs4Iml8dOylEHfJPFebsjajYdhLCpQmixt3x/ME0GFhV4XroC2EMSLHpBug", "ATNI0/LftyQNuG0Wy32LIdyNPxWMbzTd8bqorUnmH2MuFR0KFkTFyBIxLqkRrXBj+RV5izF8RtxC9anZoktp3e0KAY42IpiUm4tF8lK5r0WWzFbIBLbP34ETM+vWsZlA22RunaaH9utpOD2/8MR59Be78EvsEJxraGltq1VIovwg", "53189903738540097824627820920800539709883666819736999499705363292067908869909", "24465380776186970170394645958266108398568768137139131777892582333810663124867", "auth1:machine123", "RE0yT9l1y/QMK7PngrboWlvTOVtSZexw9uOjz+i51B9q9Dtfq8qh9Vt/X38SYIit9XiD0IxDYI+um6bn5WPYxBMq+f5fGCCr1jjNu4+/TAV+PV2n+wYfNDVW2ukbaNq/XRAOLxJTAqjL+Pz2KTVw4j/OaOAxcHEm7nP+9/ID25osA0J4WeqI2hrPaLAZDfRHEirt7W9UgNb5w7pIYkhvYg+Y7wOlIz4WFrLncz57w4Fnan7lOQaXfiYpaVX8Akq8XKuXTdg3WE1joORn5a8JQAWFVtkRszcNeru4PnYrCmMSo7ctHtlya9XmAYiblV9SdxhgNdjoHbjpvmzIz9s1jTgnQ0jMoIGn0C28SBoUY0xvaQ/MB7EsEmJXFAPg3kjBPesDaOSlb9Idg/PnczFahyvPSrZfpl9nQ+O6FBeYBsFCB6x40S8m5fwtg1ijf/OtlIPuSb6IEATCoFaN7KN3F3D10VBaMh3hESBFudeiv6/Lk7U1RKU5QkfpptQZ/eHC", "AXtlsmi7zOlT4yjCoQDp5pNFYNlUtv/6/jOMDmv4WUXsM0d4+97CPoaZaj07LsGuM45qomaoVE40QE6om8g6kEoN5wVsviFb3BzPkxVdXj57NPvFgSG2cLyMjCnXxWeXikB59Ic3N3jRXMPtJT8rW6xDsCO27bDVunbImchBL6CV", "16202273152742617592562866871810001511457182160752331809470171395714986298595", "28538857371639543047037204723412021982173158935789665121972573483633103186399"}
var auth2Param = []string{"auth2", "65000549695646603732796438742359905742570406053903786389881062969044166799969", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGPtQHjSqOH+apv7LhhhNwh7luI0SC1tZ4YXKxsXgiWZQ==", "AS7MpEb/bz1NA8dum1x1Lyi8N7NkywWsSjfrMuHDJFlwjyU4b3LJRiuBWX1lriCSxLl3khVdzarTK4pt1BeSU0wtsQ71IzsP45Yrnuaku8K1veAaVPNRPULfly4SjzG/EidOV0foyvrMNxbMhpnbebIvDk/zwj6Jj2lEIKO+MIel", "Ltzr5bSo0lY4xO2nLlF1Rzn9KFMQLxvUc6hNVzn4upJf5qyNFlXGOcQCYmAJmVyDKYxJXXvm6KXlMg9CFjc6iA5p/LgYJAIx764tNRH9fkDZNCXqmm+/Xq2Hz6zP+RJybLPHTV7aQrGgMjrRNHdsPkyTLJFbHiBzIYR4cy/ej54uHdzewL+zYYEMO/eFX4zED291gqduyoo6y+Vw/7h0h3h25PCNm3+6wgUZ1zx9bWyZX0mxGVoleaiOC0shgIplVvU6o4SqXvHP2pcoS82BnNumDvbdWFpgV0yw5z5A/IZ1Yia6uuz9clABpO7FWUSKEHTaOKuJxykMAYgcoBlC60PyTA6892h9NU0v/SepFOd7pZ06nj+a++OZEhTke6W7Hfsl5+pCFK9WAbCnmJFt/M+YkFpkQi3xAhapOs9izz1+MlwBVaMZ2Km36Ctt512nGpDwzEcdVmeTDI88Ox2/Q4S6Fg/VwO/PAZqzzYugE9rTGedosSicQNLC4YyFHhTr", "auth2:attester", "PN2/pzg3ypR2dmH7TmCevDXRchpVvQWfKGm0N3ezDdcSYnnE/XSql3UWfxSRIY7KjtKpR1Ygx8ReD0hcjlgRVicGPbIGqcPKdSk1YV4M6bITHTFo0Jmk/0RWGomgIc+NJoWamC3M585O+j0LlDdTKOXYmGP1uHKrQirP1kOHFp1XjP2+X58+6ME93pak0zlB5kgrRITQXZ6Fpv+C60AG2yGPPIPw3H5fl1w7gCnheYmbXEEnZjGiiNS975sIju6fjZMyY18HPutHcfd3n+F2h7GKcL6ep//CrT7TNoAJXS021cspJpRLiupA9+eaxhUKb0ansSQ0oJEUGILEHMhg8I3q+iDJLvU9lh8PWsrClEc6Ezvkxt4qUryMEbBmqInIWiLxzElUG9KmqlaBH3cQVCdbmPkYCPToAWJB8d08joALIccAcT8e2H+62zzLbcH+5xPUYv6l2Od5zr/xwg4nyihdX3//r3cg4KCpeGVSiRS6/IpKquF/B0ktJMqyDQpi", "AXXg0CIcuKkabOpiJyuK/4LQGbqqyPcZBN5AaCAihc2QXMebWSJTlVNuvQbKcUuY2OZgACx+5AzqEFD4GFc46aoTvtd3vWoqOeerYqqiNR9oYTfB3dQvPSaReqDIMVD6vluQf7flc7Ve+u5J/JjbVRRh4L0QOL+PnjXJYe8NnnHT", "34550967238719655950902241718186757025745215118965191068615138264162726374937", "20285643411204653950204191914920694709516395440370039260523986373208310678903", "auth2:admin", "JSxI55o1jTUesnKEbvmsuqcS/rwoRh4ufI+0deuXR22LK6aCTS6QvuiGIWRZETIh1uoInAx8luF1SFED3kC85xWr2Mnvy9b0YI5coBgYwU0vlC3W5wMPs815Q2/ApISxEL2qOtezsScGUD0qn+PFshmCAcoysq0lnmVljFvIJuF/dqNT/DpcypcHl7T0HjJbdx7pa4i+i5lcK4vH3mAnNhLpUcIgpFrvbm3JPKEMoNhrPu5c4UPDUSf+RYeKP53mS2+XHUxs2IYa6B8PrIKmhqPpnoPZEvKFAH2cN6uX8Llq+uXsbKsKbrgnRkLtgvMS5ly4fRI0mqR4qM7fGvBd0gDAWzhg908UXIhDl3PGzKzqMwDmM4qJ9CVMxNqCW7psdHl/WvcSQdG9Xww3o5NF+5aa+B4fmUF/PKYCUvg2timI3R4Jx1wRm5gRAodiYtRGWSPiqVFnh5KPwP4cKvEkEHU5FECLV4aVu4iJienhALpqBS2jnMhyKm+8GtocQNOJ", "AT+/oSedtj6tihaSiK8FGpgLuCN8YTp4r1ue0hip7x+uBVNTTZVD3VYjDvZ2b8Nym2/s+ejBuN5PHAXL+QEzdcMM2+RtM2DPzA/pmw4s/hZqMBwUHq9M6y5zSScfI7ALlmzssuefkEKo4vfdhTvxAxM3/giCSSDrSAhzBvNGb3Vt", "57998164329948855159328573606644618850776509549813340558895918680558175163795", "60104962394456759678145981572743197582245138402541568082643901283498189736926", "auth2:recovery", "MKi9FUKJjOP4bf7u0PZD97ZTHPhOuxOx5zMsOsVTzYtbUQciep4+EeYUKYtoOeqAdqyaw379Sx7FHRbS35S5NR2O+Qni1K4VsErbc/o2R0Mi0zQG7z+LaIpigb34iTTigxQcjItLPylnMD6IMKhrrrBEnNxklZOIefBb/GmJs7SGig40UEOP0JmIIpidJxVAoHmRheogZ3xbkbk0kBZvEG9ql2McKYIDWjB/nWlndGpakeFrdoTCeLuaHt+fVABxLN+qs2bBBE8PI/qTNSLS4tf2Ce12RB4wSh+TI8lmbmN8Ck5FXCtQ0zFM3EMORFqtpD7mwHnZRtoA8WARXjfMwV8zscDSU9TgOZ83kXRSqv2t/qMPe4ynxZ9UO00jRRKDffiJel2SfpzrYt+6vkUEsvtpWX5/JaRwwFi20ULLwUMyD4mSkmAPpGpworIs6Ij5nz2ZC3eZ+YeGzn/i3mPPVmh1Qej4l4yvXOhFzxD/eGHNWQZSTDiB9wIsRaUz7oPi", "AY18u6XC68s0lmu0KsWW5FDhzMFh5qml1yC5DFoKfq9ZDeY82H4D/dxqnQbxZBmm/w/OvyTS56x7YIGHuLMtMx1aDxXvG4Iu7Mi3eM9PFd9o7sV+S8OFPBahf5h9lUe95FeEKfyhRbzWPeU4XRYEPQL1Zaxe6wKzkE3/PtaL1Mfw", "2748996785901393891559154097313372810421782205593329959029835767139450666319", "34933839100176397109498942720702490398999023317914954009653681109474281043408", "auth2:machine123", "NJzTnjMxZ3chgh4L1fGXjOaC4S87r78bT6iIOu7hvD2KfwjU9MQWp5IhbT238ktIEG9OyDKPiATCr3ooogrKXyrNcxYNz40sTby2OQGh889jUX25PdKAC3r0NlbJZ/TQcARBc1scWoAB36oAwZssyfFbg2XlCxQJ0m6fdTvhLwsMM7/Jjuc6DgAns2VDTHjxRRTDOSGVlJ/OuRuMA/cv6A53yO0cYBxOFlUakTjkAWWeqPV9nBTTuzcsN1VlxN/ABbuFJ8WSCgd99bRfQrruNksSTqL6GEOBZ/AyXBEGQhcohFDv7LK9sqPuEodzPvOm7KpXR6QsZtWs6FE/kB0kQk0M9ETcdTQql2oZOd8qEAm78xYokJ8w+GsyW3Dk2K3ALAnpQ2Q6w4weyJuN9Ro5VP60iUNswHtDoGphvJUcBSNW3Y1YR9ErChfejLN/nUBr+7pdtfAdE3Ic7w44F5ZTln+rptCUFoLPMwiHgOQ8RZIxaqgw2PlM6be9BxQJtDrO", "ASQp7It1TGvP55v9IptkPn/0/M8qWf1jG1bz6cEGVOStJ2lSowF1Kl4OSoZIfit50f54HGag9Mlm6pgDxSTMTlAAvE3vItyaQcUky8At7Wdrm0U6sGedw4Aji9/PPWeS3VyDU5lDzltSmq8gJujfJ/pOke9755MDnylHNRnV1OXB", "44994125731737796954476312686732404079434715075589445279024597060619483051356", "1049657174326235170893932645169883085652814799650894807991760752808433508714"}
var auth3Param = []string{"auth3", "65000549695646603732796438742359905742570406053903786389881062969044166799969", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGPtQHjSqOH+apv7LhhhNwh7luI0SC1tZ4YXKxsXgiWZQ==", "AS7MpEb/bz1NA8dum1x1Lyi8N7NkywWsSjfrMuHDJFlwjyU4b3LJRiuBWX1lriCSxLl3khVdzarTK4pt1BeSU0wtsQ71IzsP45Yrnuaku8K1veAaVPNRPULfly4SjzG/EidOV0foyvrMNxbMhpnbebIvDk/zwj6Jj2lEIKO+MIel", "Ltzr5bSo0lY4xO2nLlF1Rzn9KFMQLxvUc6hNVzn4upJf5qyNFlXGOcQCYmAJmVyDKYxJXXvm6KXlMg9CFjc6iA5p/LgYJAIx764tNRH9fkDZNCXqmm+/Xq2Hz6zP+RJybLPHTV7aQrGgMjrRNHdsPkyTLJFbHiBzIYR4cy/ej54uHdzewL+zYYEMO/eFX4zED291gqduyoo6y+Vw/7h0h3h25PCNm3+6wgUZ1zx9bWyZX0mxGVoleaiOC0shgIplVvU6o4SqXvHP2pcoS82BnNumDvbdWFpgV0yw5z5A/IZ1Yia6uuz9clABpO7FWUSKEHTaOKuJxykMAYgcoBlC60PyTA6892h9NU0v/SepFOd7pZ06nj+a++OZEhTke6W7Hfsl5+pCFK9WAbCnmJFt/M+YkFpkQi3xAhapOs9izz1+MlwBVaMZ2Km36Ctt512nGpDwzEcdVmeTDI88Ox2/Q4S6Fg/VwO/PAZqzzYugE9rTGedosSicQNLC4YyFHhTr", "auth3:attester", "P+kiF5kUtn5o3RboEU6pFIZ2v+FSwf1SZYEEYVa9srMxzK9Bo5YMmnnI33L9xoX61jZkBapilkx0r13Epdhj0F2Xti7KZIV4rBXbi7hwcM/lEUE3q4cTc/JLGoT8rn8uRscShzAsq/7vzDawYN2DhklKNVq+IFmEyJYVGPnM11FwLFCkNhuO8WdelDHF9X7sw13ruipI2MU12xTWifCeto+XmSFKwwr6hlRtlDaDEEaiaht8BIk36eAQcf2xhmpIeDj8CRqH3kbi5hBRK6ucPR30IOKnn7+Aq/k9TiO6GkcZX2mvMIf10DwiYV2KraP6yv5gtOAEK7eLhS8vuXPQcAp/x3MzH4a8ILBc6PVboUhE/AwsPsrHG2Mi+PLjt3PeBLLEXy9/gEQ0lUnNy0pvFYNHBB33FJ0WayGtGhV9/XaPH/5hlEJph67fL0p4Kxi8pbzSGOhrk4DI+Sppd0lykl9pNJr+TyK/MdGLECqSw3i1oyb6Ck4vQ4/3+xCTKNiz", "AR/h+x+wCoUPzLofndzaINp6oB654Q/NJC0Ghi0veQoMOQsUCGlVNNj2E7p9xa9qD46n+FhbLb9wGrw2I9ofvJhVqSmtaz9hKWRtlNjLSr8b8SbyvnN0k2j8isYJPOsRj0iHOZdTv0sOx5A8X0iFaFKgC2Hvjc2CSx4iTeAE6woZ", "6792049016481571832422054444638371574293367000705517136922691136440370614961", "11224553403289079117066543269595671335507754961440863689114334506840989255452", "auth3:admin", "HQ5zmNx9J3Hc4x7JVZSFvjPtxLh0S8eFqB5ZAkeSb/p3fUghVAuZ9zp9kCoxvQa5i5TDMj8lJchHyG6+dMiWr4B47CZNxryCv5xxb9AghxFxFtCC6PWjuKXbYdmpRijGAYazqFrsTXXNOMRI+Bq2OSouvkZaKEICSVyJu2/z0rsEjxuZQLH0t+ngrieY5RhYdAVnmrqJt/dVKwYF4r6tbkEtiGiBG7644Q9PIix+s/F59A9ud+iJYS1c060BdDPnd0VvZioKyJrwtV8oLv07SLtW0Wo12UTdabwK5LGaoeh4JaOZPvZ2miGDcCzRit6u3ZHZ2YGVrvkM31yDrYQ360XFJ48lzzxHHLRikPVOSXQN6/Ftw8t7DKVPY+sRSOqYgSA+NjNkV6BakIrv93It+eKJ2UIry3LNZyQG1CDmcxpe/NWHu8EzoSGsIpELXS5QMXb7rZtaawNyO9h1081FuEUJ6XPmC0J1g93AvHbsjR1svDMfhjCK5RwDvcELNlfP", "ATiEEskpJkjFvvvVN45YtQv6BAbBijr+yefjROK/NTe5HuCoppTxzh4t6bgs1zZ35b4QKQTKvUOHUqOpHpkmudxiul22buCbDW8mjv8WwN/SGqXxKrt6DxDtaeAgiiYxPC0i0hN8TSAzDdatoUnTrz1GCZfYo2PtcXN5w6qcR3/C", "493736843762662669144138518748467858858421532180167619410568036801651496604", "29924657294152446982493634018843929372702025697454881207515629162909749108388", "auth3:recovery", "ZMLY1aY0KOEg1fJQZn4FMDoUa4VakneDlW1cHhMlsiUUz8cE9my1eymwmgZ99Mf/2eY5u0pB8wKKYG10eQAWo0skRiIk8q/xpMzgBch7qJQ9w9xNRwwIogtMVCKRJgzrD26Mo0Van1ehOyfRmZOiUhH9ptvZ4iflFbA0Xz1XuZZqyEcZAriusbwo0j09y0BsmEEuS4dTyrnJVhQauvIcgkIXvTb69mBg57VCVv4a6h9GxH+sI/GvAoOIGm0xQ8CLWPeWvbYyApU/v8LVtsMzjhM6aS6dGr58lTfa2q/+UdgktqEX6kvbY1N3U2oiadJsvnJJr8EdMR7EmDKw92mfjRt9Ahabp3Lw8Y7gislF2IlyY0/SoOVrkUrtKeHBJH6CRMcHi4OomG4Fy6TSMQGqmkDl8QjYz9wqjytX8asyG6tlV6+92ibAcoCjSSdjs6KFM7PhYkigvi64O5kg4ZSLmSGt3ULWcXYgpdNIkKbdSgkLfqhW3u6IXnt2Y1w1hOSd", "ARWFpMrMgA1MQ+fIJxDIX1YxefuAGsrdClQG/ZxIv9ssarDL/W1CDWnd+bEoIdV+we7IoQDTW89w1WFJP88dg3poKZ3ElvhoQV3krzibuiS+gYR3qIt4B2jz0aYW9Wbz2ioX6sazsNbvm5DAaEWtXEF5AdC580zFIP35E2zIQbya", "37640140677166044971912521453540781840678518547008442304596771686128123668856", "22636158553634890472315920699240276549320905841760768601790093935848177204542", "auth3:machine123", "PoOlBp07yY37OgBHOtdGq0kv8dEUV3TjOLCh26G7COh3g+jYFSuyNkAq5t9qSS3Zrs5LuizPedWlGcufWO4mpw7QbzIkjuV3YtGWoFZCD4rCVXIHXHQpV4c0nOka6vYsVqHDYvjrwlTMAfWhP92JX9Qq879sVCQBLunljG+2TPco28i9yl2G30GHtONG6eSiH0bA+GLU2gG+ygFfco7cgg8Cr6hdCwipNx21j97xmTqC9Yk1q+yA3PKE7/RdTSwwRRI3z5JNiXbkCkf6XhO8zVcgvbB3YJllmfNql56TsvaB3LOiuKM1tYefeBuRZ0j2d4Zg+HiF5/8ZddfyvPjgMh7OJkYL8RzPwFoxjMLnn6j5yZZrsBJ8d4OySV6HNNqOjBv5gnkloieaBeOm7diaywNZan4bBlxj14wA+9HE1c6D9r4Z66SFfElwd15uUUIdwapOoWCrJnDS6tCkyUeijCTFH0ISLRqrmAIqz73qI1X/zCUff0IydwT7Rx2T1251", "ASJLP6iCYguqD5cwbVTRpgyj44cJCnA9AiitGV2ROd5Sji6YF97nOZzqoS5fgtLtOW5JyLuFeH+J3+KzcembBrlkOaz1JcjmyrIQmLMgD76BpFxDcCezVpqC9wD/l0cuQIdZeXHILBuIKdlQmY35LLtBnGtdrDm0lgTgntdV44N1", "6974545074354669526389036805409185417317319870717073352095395086467794693723", "48503931390687740644556267735422343233291020020323945629984610746897788249041"}

// var userRecord map[string]string = make(map[string]string)
// var userTokens map[string]*AuthToken = make(map[string]*AuthToken)

func HomePage(auth *abe.MAABEAuth, w http.ResponseWriter, r *http.Request) {
	if auth == nil {
		fmt.Printf("Authority not initialized!")
	}
	n, err := fmt.Fprintf(w, "Authority %s - server running.", auth.ID)
	if err != nil || n == 0 {
		fmt.Printf("Failed to print status message: %v", err)
	}
	fmt.Println("Served a request for home page.")
}

func GetPubKeys(auth *abe.MAABEAuth, w http.ResponseWriter, r *http.Request) {
	jsonBytes, err := maabe.PublicKeyToJSON(auth.Pk)
	if err != nil {
		fmt.Printf("Error marshaling json: %v\n", err)
	}
	n, err := fmt.Fprintf(w, "%s", string(jsonBytes))
	if err != nil || n == 0 {
		fmt.Printf("Failed to print public keys: %v", err)
	}
	fmt.Println("Served a request for ABE public keys.")
}

type GetAttributeKeysForm struct {
	Uuid    string   `json:"uuid"`
	Attribs []string `json:"attributes"`
}

func GetAttributeKeys(auth *abe.MAABEAuth, w http.ResponseWriter, r *http.Request) {
	// the authenticated user requests attribute keys
	// INPUT: access token, gid, list of attributes
	// OUTPUT: list of attribute keys
	switch r.Method {
	case "POST":
		check := signature.CheckRequest(r.Header, w)
		if check == false {
			return
		}
		// json unmarshal request
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}
		var form GetAttributeKeysForm
		err = json.Unmarshal(body, &form)
		if err != nil {
			fmt.Printf("Error unmarshaling json: %v\n", err)
			http.Error(w, "Invalid json", http.StatusBadRequest)
			return
		}
		// check if attribute can be delegated
		// todo
		fmt.Println(form)

		// generate attribute keys
		attribKeys, err := auth.GenerateAttribKeys(form.Uuid, form.Attribs)
		if err != nil {
			fmt.Printf("Error generating attribute keys: %v\n", err)
			return
		}
		jsonBytes, err := maabe.AttribKeysToJSON(attribKeys)
		if err != nil {
			fmt.Printf("Error json-marshaling attribute keys: %v\n", err)
			return
		}
		n, err := fmt.Fprintf(w, "%s", string(jsonBytes))
		if err != nil || n == 0 {
			fmt.Printf("Error printing status: %v", err)
		}
		fmt.Println("Served a request for private ABE keys to "+form.Uuid+
			" for attributes ", form.Attribs)
	default:
		n, err := fmt.Fprintf(w, "Request method %s is not supported", r.Method)
		if err != nil || n == 0 {
			fmt.Printf("Error printing status: %v", err)
		}
	}
}

func MaabeService() {
	var err error
	scheme := abe.NewMAABE()
	if err != nil {
		fmt.Printf("error generating maabe scheme from data: %v", err)
		os.Exit(1)
	}
	// get auth id from env
	id := os.Getenv("AUTH_ID")
	if id == "" {
		// default value
		id = "auth"
	}
	if id == "auth1" {
		auth, err = maabe.MaabeAuthFromRaw(auth1Param)
	} else if id == "auth2" {
		auth, err = maabe.MaabeAuthFromRaw(auth2Param)
	} else if id == "auth3" {
		auth, err = maabe.MaabeAuthFromRaw(auth3Param)
	} else {
		fmt.Printf("BEWARE: generating new authority\n")
		auth, err = scheme.NewMAABEAuth(id, []string{id + ":attester", id + ":admin", id + ":recovery", id + ":machine123"})
	}
	if err != nil {
		fmt.Printf("Error initiating authority %s: %v", id, err)
		os.Exit(1)
	}

	for i := 0; i < 10; i++ {
		auth.AddAttribute(id + ":test_attribute" + strconv.Itoa(i))
	}

	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		HomePage(auth, writer, request)
	})
	http.HandleFunc("/pubkeys", func(writer http.ResponseWriter, request *http.Request) {
		GetPubKeys(auth, writer, request)
	})
	http.HandleFunc("/get-attribute-keys", func(writer http.ResponseWriter, request *http.Request) {
		GetAttributeKeys(auth, writer, request)
	})
	http.HandleFunc("/pub-signature-keys", func(writer http.ResponseWriter, request *http.Request) {
		signature.SignatureKeys(VerificationKeysDataset, "fame_key_authority/single/certs/HEKeyManager.key", writer, request)
	})
	// determine port from env
	port := os.Getenv("AUTH_PORT")
	if port == "" {
		// default value
		port = "6900"
	}
	if _, err = strconv.Atoi(port); err != nil {
		fmt.Printf("AUTH_PORT should be a number: %s\n", port)
		os.Exit(1)
	}
	fmt.Println("Auth running on port ", port)
	err = http.ListenAndServe(":"+port, nil)
	if err != nil {
		fmt.Printf("Error listening: %v", err)
		os.Exit(1)
	}
}
