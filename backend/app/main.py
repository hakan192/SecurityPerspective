from fastapi import FastAPI

from app.api.routes import router
from app.db.session import Base, engine, SessionLocal
from app.models.entities import BaselineControl

app = FastAPI(title='SecurityPerspective API')
app.include_router(router, prefix='/api/v1')


@app.on_event('startup')
def startup_event():
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        if not db.query(BaselineControl).first():
            db.add_all(
                [
                    BaselineControl(
                        control_key='sql_injection',
                        category='Threat Prevention',
                        description='SQL injection signatures enabled',
                        required=True,
                        weight=1.5,
                    ),
                    BaselineControl(
                        control_key='bot_protection',
                        category='Threat Prevention',
                        description='Bot mitigation policy enabled',
                        required=True,
                        weight=1.0,
                    ),
                    BaselineControl(
                        control_key='tls_hardening',
                        category='Transport Security',
                        description='TLS 1.2+ enforced and weak ciphers removed',
                        required=True,
                        weight=1.5,
                    ),
                ]
            )
            db.commit()
    finally:
        db.close()


@app.get('/healthz')
def healthz():
    return {'status': 'ok'}
