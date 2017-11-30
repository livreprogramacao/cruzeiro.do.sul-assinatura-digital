
package teste;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;


/**
 * <p>Classe Java de documentoEntregueModel complex type.
 * 
 * <p>O seguinte fragmento do esquema especifica o conteúdo esperado contido dentro desta classe.
 * 
 * <pre>
 * &lt;complexType name="documentoEntregueModel">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="codigoInstituicao" type="{http://www.w3.org/2001/XMLSchema}int" minOccurs="0"/>
 *         &lt;element name="rgmAluno" type="{http://www.w3.org/2001/XMLSchema}long" minOccurs="0"/>
 *         &lt;element name="nomeAluno" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="codigoDocumento" type="{http://www.w3.org/2001/XMLSchema}int" minOccurs="0"/>
 *         &lt;element name="nomeDocumento" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="sequencioDocumentos" type="{http://www.w3.org/2001/XMLSchema}int" minOccurs="0"/>
 *         &lt;element name="idArquivo" type="{http://www.w3.org/2001/XMLSchema}long" minOccurs="0"/>
 *         &lt;element name="caminhoArquivo" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="nomeArquivo" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="extensaoArquivo" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="dataBaixa" type="{http://www.w3.org/2001/XMLSchema}dateTime" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "documentoEntregueModel", propOrder = {
    "codigoInstituicao",
    "rgmAluno",
    "nomeAluno",
    "codigoDocumento",
    "nomeDocumento",
    "sequencioDocumentos",
    "idArquivo",
    "caminhoArquivo",
    "nomeArquivo",
    "extensaoArquivo",
    "dataBaixa"
})
public class DocumentoEntregueModel {

    protected Integer codigoInstituicao;
    protected Long rgmAluno;
    protected String nomeAluno;
    protected Integer codigoDocumento;
    protected String nomeDocumento;
    protected Integer sequencioDocumentos;
    protected Long idArquivo;
    protected String caminhoArquivo;
    protected String nomeArquivo;
    protected String extensaoArquivo;
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar dataBaixa;

    /**
     * Obtém o valor da propriedade codigoInstituicao.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getCodigoInstituicao() {
        return codigoInstituicao;
    }

    /**
     * Define o valor da propriedade codigoInstituicao.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setCodigoInstituicao(Integer value) {
        this.codigoInstituicao = value;
    }

    /**
     * Obtém o valor da propriedade rgmAluno.
     * 
     * @return
     *     possible object is
     *     {@link Long }
     *     
     */
    public Long getRgmAluno() {
        return rgmAluno;
    }

    /**
     * Define o valor da propriedade rgmAluno.
     * 
     * @param value
     *     allowed object is
     *     {@link Long }
     *     
     */
    public void setRgmAluno(Long value) {
        this.rgmAluno = value;
    }

    /**
     * Obtém o valor da propriedade nomeAluno.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getNomeAluno() {
        return nomeAluno;
    }

    /**
     * Define o valor da propriedade nomeAluno.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setNomeAluno(String value) {
        this.nomeAluno = value;
    }

    /**
     * Obtém o valor da propriedade codigoDocumento.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getCodigoDocumento() {
        return codigoDocumento;
    }

    /**
     * Define o valor da propriedade codigoDocumento.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setCodigoDocumento(Integer value) {
        this.codigoDocumento = value;
    }

    /**
     * Obtém o valor da propriedade nomeDocumento.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getNomeDocumento() {
        return nomeDocumento;
    }

    /**
     * Define o valor da propriedade nomeDocumento.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setNomeDocumento(String value) {
        this.nomeDocumento = value;
    }

    /**
     * Obtém o valor da propriedade sequencioDocumentos.
     * 
     * @return
     *     possible object is
     *     {@link Integer }
     *     
     */
    public Integer getSequencioDocumentos() {
        return sequencioDocumentos;
    }

    /**
     * Define o valor da propriedade sequencioDocumentos.
     * 
     * @param value
     *     allowed object is
     *     {@link Integer }
     *     
     */
    public void setSequencioDocumentos(Integer value) {
        this.sequencioDocumentos = value;
    }

    /**
     * Obtém o valor da propriedade idArquivo.
     * 
     * @return
     *     possible object is
     *     {@link Long }
     *     
     */
    public Long getIdArquivo() {
        return idArquivo;
    }

    /**
     * Define o valor da propriedade idArquivo.
     * 
     * @param value
     *     allowed object is
     *     {@link Long }
     *     
     */
    public void setIdArquivo(Long value) {
        this.idArquivo = value;
    }

    /**
     * Obtém o valor da propriedade caminhoArquivo.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCaminhoArquivo() {
        return caminhoArquivo;
    }

    /**
     * Define o valor da propriedade caminhoArquivo.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCaminhoArquivo(String value) {
        this.caminhoArquivo = value;
    }

    /**
     * Obtém o valor da propriedade nomeArquivo.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getNomeArquivo() {
        return nomeArquivo;
    }

    /**
     * Define o valor da propriedade nomeArquivo.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setNomeArquivo(String value) {
        this.nomeArquivo = value;
    }

    /**
     * Obtém o valor da propriedade extensaoArquivo.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getExtensaoArquivo() {
        return extensaoArquivo;
    }

    /**
     * Define o valor da propriedade extensaoArquivo.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setExtensaoArquivo(String value) {
        this.extensaoArquivo = value;
    }

    /**
     * Obtém o valor da propriedade dataBaixa.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getDataBaixa() {
        return dataBaixa;
    }

    /**
     * Define o valor da propriedade dataBaixa.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setDataBaixa(XMLGregorianCalendar value) {
        this.dataBaixa = value;
    }

}
