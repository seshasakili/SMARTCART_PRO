from xhtml2pdf import pisa
from io import BytesIO


def generate_pdf(html):

    pdf = BytesIO()

    pisa_status = pisa.CreatePDF(

        html,
        dest=pdf

    )

    if pisa_status.err:

        return None

    pdf.seek(0)

    return pdf.getvalue()
